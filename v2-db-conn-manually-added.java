import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.jdbc.datasource.lookup.DataSourceLookupFailureException;
import org.springframework.lang.Nullable;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*; // For Controller
import org.springframework.http.ResponseEntity; // For Controller response
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap; // For thread safety
import java.net.URI;
import java.net.URISyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean; // To access resolved data sources

// --- 1. Tenant Context ---
// (No changes needed here)
class TenantContext {

    private static final Logger log = LoggerFactory.getLogger(TenantContext.class);
    private static final ThreadLocal<String> currentTenant = new ThreadLocal<>();

    public static void setCurrentTenant(String tenantId) {
        log.debug("Setting tenant to: {}", tenantId);
        currentTenant.set(tenantId);
    }

    @Nullable
    public static String getCurrentTenant() {
        return currentTenant.get();
    }

    public static void clear() {
        log.debug("Clearing tenant context");
        currentTenant.remove();
    }
}

// --- 2. Tenant Interceptor ---
// (No changes needed here)
class TenantInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(TenantInterceptor.class);
    private final String defaultTenantId;

    public TenantInterceptor(String defaultTenantId) {
        this.defaultTenantId = defaultTenantId;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String tenantId = resolveTenantId(request);
        log.info("Request received for host: {}, Resolved Tenant ID: {}", request.getServerName(), tenantId);
        TenantContext.setCurrentTenant(tenantId);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        TenantContext.clear();
    }

    private String resolveTenantId(HttpServletRequest request) {
        String host = request.getServerName();
        if (host != null && !host.isEmpty()) {
            return host;
        }
        log.warn("Could not resolve tenant ID from host: {}. Falling back to default tenant: {}", host, defaultTenantId);
        return defaultTenantId;
    }
}

// --- 3. Multi-Tenant DataSource Router ---
// Extends AbstractRoutingDataSource and allows adding new DataSources dynamically.
// Implements InitializingBean to access the resolvedDataSources map.
class MultitenantDataSource extends AbstractRoutingDataSource implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(MultitenantDataSource.class);

    // Use ConcurrentHashMap for thread-safe access if adding tenants dynamically
    private final Map<Object, DataSource> resolvedDataSources = new ConcurrentHashMap<>();
    private final Object lock = new Object(); // Lock for adding datasources

    // This map holds the configuration passed initially
    private Map<Object, Object> initialTargetDataSources;

    @Override
    public void setTargetDataSources(Map<Object, Object> targetDataSources) {
        this.initialTargetDataSources = targetDataSources;
        super.setTargetDataSources(targetDataSources);
    }

    @Override
    @Nullable
    protected Object determineCurrentLookupKey() {
        String tenantId = TenantContext.getCurrentTenant();
        log.debug("Determining DataSource for tenant: {}", tenantId);
        return tenantId;
    }

    // This method is called by Spring after properties are set.
    // We override it to populate our own resolvedDataSources map.
    @Override
    public void afterPropertiesSet() {
        if (this.initialTargetDataSources == null) {
            throw new IllegalArgumentException("Property 'targetDataSources' is required");
        }

        // Resolve initial DataSources from the configured map
        this.initialTargetDataSources.forEach((key, dataSource) -> {
            if (dataSource instanceof DataSource) {
                this.resolvedDataSources.put(key, (DataSource) dataSource);
            } else {
                // Handle cases where lookup might be needed (though less common with direct DataSource objects)
                log.warn("Target DataSource for key '{}' is not a direct DataSource instance. Type: {}", key, dataSource.getClass().getName());
                // Potentially add lookup logic here if needed based on superclass behavior
            }
        });

        // Set the default target DataSource if configured
        if (getDefaultTargetDataSource() != null) {
             if (getDefaultTargetDataSource() instanceof DataSource) {
                this.resolvedDataSources.put("default", (DataSource) getDefaultTargetDataSource()); // Use a known key or handle default separately
             }
        }

        log.info("Initial DataSources resolved. Count: {}", this.resolvedDataSources.size());
        // We don't call super.afterPropertiesSet() here because we are managing resolution ourselves
        // to allow dynamic additions.
    }

     // Override resolveSpecifiedDataSource to use our map
    @Override
    protected DataSource resolveSpecifiedDataSource(Object dataSource) throws IllegalArgumentException {
         if (dataSource instanceof DataSource) {
            return (DataSource) dataSource;
        } else {
             // Add logic here if you support DataSource lookup names (less common for dynamic)
             throw new IllegalArgumentException("Illegal data source value - only direct DataSource instances supported currently: " + dataSource);
        }
    }

    // Override determineTargetDataSource to use our map and handle dynamic additions
    @Override
    protected DataSource determineTargetDataSource() {
        Object lookupKey = determineCurrentLookupKey();
        if (lookupKey == null) {
             log.debug("Tenant lookup key is null, returning default DataSource.");
             DataSource defaultDs = (DataSource) getDefaultTargetDataSource();
             if (defaultDs == null) {
                 throw new IllegalStateException("Cannot determine target DataSource for null key and no defaultDataSource set");
             }
             return defaultDs;
        }

        DataSource dataSource = this.resolvedDataSources.get(lookupKey);
        if (dataSource == null) {
            log.warn("Cannot find DataSource for tenant key: '{}'. Falling back to default.", lookupKey);
            // Fallback to default if specific tenant DataSource not found
            dataSource = (DataSource) getDefaultTargetDataSource();
            if (dataSource == null) {
                 throw new IllegalStateException("Cannot determine target DataSource for key [" + lookupKey + "] and no defaultDataSource set");
            }
        } else {
             log.debug("Found DataSource for tenant key: '{}'", lookupKey);
        }
        return dataSource;
    }

    /**
     * Adds a new DataSource for a given tenant ID at runtime.
     *
     * @param tenantId   The identifier for the tenant.
     * @param dataSource The DataSource instance for the tenant.
     * @return true if the DataSource was added successfully, false if the tenantId already exists.
     */
    public boolean addTenantDataSource(String tenantId, DataSource dataSource) {
        synchronized(lock) { // Synchronize to prevent race conditions during add
            if (resolvedDataSources.containsKey(tenantId)) {
                log.warn("Tenant ID '{}' already exists. DataSource not added.", tenantId);
                return false;
            }
            resolvedDataSources.put(tenantId, dataSource);
            log.info("Successfully added new DataSource for tenant ID: {}", tenantId);
            return true;
        }
    }

     /**
     * Retrieves the map of currently resolved DataSources.
     * Be cautious modifying this map directly outside the synchronized addTenantDataSource method.
     * @return A map of tenant IDs to DataSource instances.
     */
    public Map<Object, DataSource> getResolvedDataSources() {
        return this.resolvedDataSources;
    }
}


// --- 4. DataSource Configuration ---
// Sets up the initial DataSource beans and the routing mechanism.
@Configuration
class DataSourceConfig {

    private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);

    // Static/Initial tenant configuration (load from external source ideally)
    private final String defaultTenantId = "default_tenant";
    private final String defaultDbUrl = "jdbc:h2:mem:defaultdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE";
    private final String defaultDbUsername = "sa";
    private final String defaultDbPassword = "";
    private final String defaultDbDriver = "org.h2.Driver";

    private Map<String, Map<String, String>> initialTenantDatabases = new HashMap<>();

    public DataSourceConfig() {
        // Load initial tenants (e.g., from application.yml or a config DB)
        Map<String, String> tenant1Props = new HashMap<>();
        tenant1Props.put("url", "jdbc:h2:mem:tenant1db;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        tenant1Props.put("username", "sa");
        tenant1Props.put("password", "");
        tenant1Props.put("driverClassName", "org.h2.Driver");
        initialTenantDatabases.put("tenant1.example.com", tenant1Props);

        Map<String, String> tenant2Props = new HashMap<>();
        tenant2Props.put("url", "jdbc:postgresql://localhost:5432/tenant2db");
        tenant2Props.put("username", "user2");
        tenant2Props.put("password", "pass2");
        tenant2Props.put("driverClassName", "org.postgresql.Driver");
        initialTenantDatabases.put("tenant2.yourapp.io", tenant2Props);

        log.info("Loaded initial configuration for tenants: {}", initialTenantDatabases.keySet());
    }

    // Creates the primary DataSource bean, which is the routing DataSource.
    @Bean(name = "dataSource")
    public DataSource dataSource() {
        MultitenantDataSource routingDataSource = new MultitenantDataSource();

        Map<Object, Object> targetDataSources = new HashMap<>();

        // 1. Create and add the default DataSource
        DataSource defaultDataSource = createDataSource(
            defaultDbUrl, defaultDbUsername, defaultDbPassword, defaultDbDriver
        );
        // Don't add default to targetDataSources map directly, set it via setDefaultTargetDataSource
        log.info("Configured default DataSource for tenant key: {}", defaultTenantId);

        // 2. Create and add DataSources for each initially configured tenant
        initialTenantDatabases.forEach((tenantId, properties) -> {
            DataSource tenantDataSource = createDataSource(
                properties.get("url"),
                properties.get("username"),
                properties.get("password"),
                properties.get("driverClassName")
            );
            targetDataSources.put(tenantId, tenantDataSource);
            log.info("Configured initial DataSource for tenant key: {}", tenantId);
        });

        routingDataSource.setTargetDataSources(targetDataSources);
        routingDataSource.setDefaultTargetDataSource(defaultDataSource); // Set the default

        // afterPropertiesSet() will be called by Spring automatically after the bean is created
        // and properties (like targetDataSources and defaultTargetDataSource) are set.
        // Our overridden afterPropertiesSet in MultitenantDataSource handles the logic.

        log.info("Multitenant DataSource configured with {} initial target(s) and default.", targetDataSources.size());
        return routingDataSource;
    }

    // Helper method to create a DataSource instance (could be moved to TenantManagementService)
    // Make it public or move it if TenantManagementService needs it
    public static DataSource createDataSource(String url, String username, String password, String driverClassName) {
         if (url == null || url.trim().isEmpty()) {
            log.error("Database URL is null or empty. Cannot create DataSource.");
            throw new IllegalArgumentException("Database URL cannot be null or empty.");
        }
         log.info("Creating DataSource for URL: {}", url.substring(0, Math.min(url.length(), 50)) + "...");
         DataSourceBuilder<?> dataSourceBuilder = DataSourceBuilder.create();
         dataSourceBuilder.driverClassName(driverClassName);
         dataSourceBuilder.url(url);
         dataSourceBuilder.username(username);
         dataSourceBuilder.password(password);
         // Configure connection pooling (e.g., HikariCP) here for production
         // dataSourceBuilder.type(com.zaxxer.hikari.HikariDataSource.class);
         // Add pool properties: .maxPoolSize(10), .connectionTimeout(30000), etc.
         return dataSourceBuilder.build();
    }
}

// --- 5. Web MVC Configuration ---
// (No changes needed here)
@Configuration
class WebMvcConfig implements WebMvcConfigurer {

    private final String defaultTenantId = "default_tenant"; // Ideally inject this

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("Registering TenantInterceptor");
        registry.addInterceptor(new TenantInterceptor(defaultTenantId));
    }
}


// --- 6. Tenant Management Service ---
// Service responsible for adding new tenant DataSources dynamically.
@Service
class TenantManagementService {

    private static final Logger log = LoggerFactory.getLogger(TenantManagementService.class);

    // Inject the primary routing DataSource
    private final MultitenantDataSource multitenantDataSource;

    @Autowired
    public TenantManagementService(DataSource dataSource) {
        // We inject the primary DataSource bean, which we know is our MultitenantDataSource
        if (dataSource instanceof MultitenantDataSource) {
            this.multitenantDataSource = (MultitenantDataSource) dataSource;
        } else {
            // This should not happen if configuration is correct
            log.error("Injected DataSource is not an instance of MultitenantDataSource! Type: {}", dataSource.getClass().getName());
            throw new IllegalStateException("Required MultitenantDataSource bean not found.");
        }
    }

    /**
     * Adds a new tenant DataSource configuration dynamically.
     * NOTE: In a real application, tenant details should be validated and securely stored.
     * This example assumes details are provided correctly.
     *
     * @param tenantId        The unique identifier for the new tenant (e.g., domain name).
     * @param url             JDBC URL for the tenant's database.
     * @param username        Database username.
     * @param password        Database password.
     * @param driverClassName JDBC driver class name.
     * @return true if the tenant was added successfully, false otherwise (e.g., tenantId already exists).
     */
    public boolean addTenant(String tenantId, String url, String username, String password, String driverClassName) {
        log.info("Attempting to add new tenant: {}", tenantId);

        // Input validation (basic example)
        if (tenantId == null || tenantId.trim().isEmpty() || url == null || url.trim().isEmpty()) {
             log.error("Invalid tenant details provided for ID: {}", tenantId);
             return false;
        }

        // Check if tenant already exists in the router
        if (multitenantDataSource.getResolvedDataSources().containsKey(tenantId)) {
            log.warn("Tenant '{}' already exists. Skipping addition.", tenantId);
            return false; // Or handle update logic if needed
        }

        try {
            // Create the new DataSource instance
            // Using the static helper method from DataSourceConfig for consistency
            DataSource newDataSource = DataSourceConfig.createDataSource(url, username, password, driverClassName);

            // Add the new DataSource to the routing DataSource
            boolean added = multitenantDataSource.addTenantDataSource(tenantId, newDataSource);

            if (added) {
                 // Optional: Persist the new tenant configuration to your external store (DB, file)
                 // so it's available after application restarts.
                 log.info("Persistence logic for tenant '{}' should be implemented here.", tenantId);
            }
            return added;

        } catch (Exception e) {
            log.error("Failed to create and add DataSource for tenant '{}'", tenantId, e);
            // Consider cleanup if partial steps succeeded
            return false;
        }
    }

     /**
     * Lists the currently configured tenant IDs.
     * @return A set of tenant IDs.
     */
    public java.util.Set<Object> getCurrentTenants() {
        // Return keys from the resolved map, excluding any internal keys like 'default' if necessary
        return multitenantDataSource.getResolvedDataSources().keySet();
    }
}

// --- 7. Example Admin Controller ---
// Exposes an endpoint to dynamically add tenants.
// PROTECT THIS ENDPOINT APPROPRIATELY IN A REAL APPLICATION!
@RestController
@RequestMapping("/admin/tenants")
class TenantAdminController {

    private static final Logger log = LoggerFactory.getLogger(TenantAdminController.class);

    @Autowired
    private TenantManagementService tenantManagementService;

    // DTO (Data Transfer Object) for receiving tenant details
    static class TenantDto {
        public String tenantId;
        public String url;
        public String username;
        public String password;
        public String driverClassName;
    }

    @PostMapping
    public ResponseEntity<String> addTenant(@RequestBody TenantDto tenantDto) {
        log.info("Received request to add tenant: {}", tenantDto.tenantId);
        // Basic security check - replace with proper authentication/authorization
        // if (!isAdminUser(request)) { return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Unauthorized"); }

        boolean success = tenantManagementService.addTenant(
            tenantDto.tenantId,
            tenantDto.url,
            tenantDto.username,
            tenantDto.password,
            tenantDto.driverClassName
        );

        if (success) {
            return ResponseEntity.ok("Tenant '" + tenantDto.tenantId + "' added successfully.");
        } else {
            return ResponseEntity.badRequest().body("Failed to add tenant '" + tenantDto.tenantId + "'. Check logs for details (e.g., already exists or invalid config).");
        }
    }

    @GetMapping
    public ResponseEntity<java.util.Set<Object>> listTenants() {
         log.info("Received request to list tenants.");
         return ResponseEntity.ok(tenantManagementService.getCurrentTenants());
    }

    // --- Example Usage (Service/Repository - No changes needed) ---
    /*
    @Service
    class MyTenantAwareService {
        // ... (same as before)
    }

    @RestController
    class MyController {
        // ... (same as before)
    }
    */
}

// --- Notes ---
// 1. Persistence: Dynamically added tenants are currently only stored in memory. If the application restarts, they will be lost. You MUST implement logic to persist the configuration of newly added tenants (e.g., in a database or configuration file) and load them during startup in `DataSourceConfig`.
// 2. Security: The `/admin/tenants` endpoint is a critical administrative function. Secure it properly using Spring Security or similar mechanisms to ensure only authorized users can add tenants.
// 3. Error Handling: Added basic error handling, but production code should be more robust. Consider what happens if `createDataSource` fails.
// 4. Connection Pool Management: Ensure `createDataSource` configures connection pooling appropriately (e.g., HikariCP) for dynamically added tenants. Closing DataSources when tenants are removed (if you add that functionality) is also important.
// 5. Thread Safety: Used `ConcurrentHashMap` and synchronization in `addTenantDataSource` for basic thread safety. Review if more complex scenarios require further synchronization.
// 6. Dependencies: Ensure necessary dependencies (`spring-boot-starter-web`, `spring-boot-starter-jdbc`, database drivers) are present. Add `spring-boot-starter-security` for endpoint protection.
