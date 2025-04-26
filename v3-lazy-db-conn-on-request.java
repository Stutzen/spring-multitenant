import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
// Removed Controller imports as TenantAdminController is removed
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects; // For Objects.requireNonNull
import java.util.concurrent.ConcurrentHashMap; // For thread safety
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

// --- 1. Tenant Context ---
// (No changes needed)
class TenantContext {
    private static final Logger log = LoggerFactory.getLogger(TenantContext.class);
    private static final ThreadLocal<String> currentTenant = new ThreadLocal<>();
    public static void setCurrentTenant(String tenantId) { log.debug("Setting tenant to: {}", tenantId); currentTenant.set(tenantId); }
    @Nullable public static String getCurrentTenant() { return currentTenant.get(); }
    public static void clear() { log.debug("Clearing tenant context"); currentTenant.remove(); }
}

// --- 2. Tenant Interceptor ---
// (No changes needed)
class TenantInterceptor implements HandlerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(TenantInterceptor.class);
    private final String defaultTenantId;
    public TenantInterceptor(String defaultTenantId) { this.defaultTenantId = defaultTenantId; }
    @Override public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String tenantId = resolveTenantId(request);
        log.info("Request received for host: {}, Resolved Tenant ID: {}", request.getServerName(), tenantId);
        TenantContext.setCurrentTenant(tenantId);
        return true;
    }
    @Override public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception { TenantContext.clear(); }
    private String resolveTenantId(HttpServletRequest request) {
        String host = request.getServerName();
        // Basic example: use the full host name. Adapt if needed (e.g., subdomain).
        if (host != null && !host.isEmpty()) { return host; }
        log.warn("Could not resolve tenant ID from host: {}. Falling back to default tenant: {}", host, defaultTenantId);
        return defaultTenantId;
    }
}

// --- NEW: Tenant Configuration Service ---
// Responsible for fetching connection details for a tenant ID.
// ** REPLACE THE PLACEHOLDER LOGIC HERE **
@Service
class TenantConfigService {
    private static final Logger log = LoggerFactory.getLogger(TenantConfigService.class);

    // --- Placeholder Configuration Store ---
    // In a real application, this should query a database, read a file, or call an external service.
    private final Map<String, TenantDataSourceProperties> tenantConfigs = new ConcurrentHashMap<>();

    public TenantConfigService() {
        // Example: Pre-populate or load initial configs if desired (optional)
        // This could also be loaded from application.yml via @ConfigurationProperties
        tenantConfigs.put("tenant1.example.com", new TenantDataSourceProperties(
            "jdbc:h2:mem:tenant1db_ondemand;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
            "sa", "", "org.h2.Driver"));
        tenantConfigs.put("tenant2.yourapp.io", new TenantDataSourceProperties(
            "jdbc:postgresql://localhost:5432/tenant2db",
            "user2", "pass2", "org.postgresql.Driver"));
        log.info("TenantConfigService initialized with placeholder configs for: {}", tenantConfigs.keySet());
    }
    // --- End Placeholder ---

    /**
     * Fetches the DataSource properties for a given tenant ID.
     *
     * @param tenantId The identifier of the tenant.
     * @return TenantDataSourceProperties if found, otherwise null.
     */
    @Nullable
    public TenantDataSourceProperties findByTenantId(String tenantId) {
        log.debug("Fetching configuration for tenant ID: {}", tenantId);
        // ** Replace this line with your actual lookup logic **
        TenantDataSourceProperties props = tenantConfigs.get(tenantId);
        if (props == null) {
            log.warn("No configuration found for tenant ID: {}", tenantId);
        }
        return props;
    }

    // Optional: Method to add/update tenant configs dynamically if needed
    public void addOrUpdateTenantConfig(String tenantId, TenantDataSourceProperties properties) {
         log.info("Adding/Updating configuration for tenant ID: {}", tenantId);
         tenantConfigs.put(tenantId, properties);
         // ** Add logic here to persist this change to your actual configuration store (DB, file etc.) **
         log.warn("Persistence logic for tenant config '{}' needs implementation.", tenantId);
    }
}

// --- Helper Class for Tenant Properties ---
class TenantDataSourceProperties {
    final String url;
    final String username;
    final String password;
    final String driverClassName;

    public TenantDataSourceProperties(String url, String username, String password, String driverClassName) {
        this.url = url;
        this.username = username;
        this.password = password;
        this.driverClassName = driverClassName;
    }
    // Getters can be added if needed
}


// --- 3. Multi-Tenant DataSource Router ---
// Modified to create DataSources on demand.
class MultitenantDataSource extends AbstractRoutingDataSource {

    private static final Logger log = LoggerFactory.getLogger(MultitenantDataSource.class);

    // Map to cache the resolved DataSource instances
    private final Map<Object, DataSource> resolvedDataSources = new ConcurrentHashMap<>();
    private final Object lock = new Object(); // Lock for creating/adding datasources

    // Service to fetch tenant configurations
    private final TenantConfigService tenantConfigService;
    private final String defaultTenantKey; // Identifier for the default tenant

    public MultitenantDataSource(TenantConfigService tenantConfigService, String defaultTenantKey) {
        this.tenantConfigService = Objects.requireNonNull(tenantConfigService, "TenantConfigService cannot be null");
        this.defaultTenantKey = Objects.requireNonNull(defaultTenantKey, "Default Tenant Key cannot be null");
    }

    // Set the default DataSource (called from DataSourceConfig)
    public void initializeDefaultDataSource(DataSource defaultDataSource) {
        if (defaultDataSource != null) {
            this.resolvedDataSources.put(this.defaultTenantKey, defaultDataSource);
            super.setDefaultTargetDataSource(defaultDataSource); // Also set it in the parent
            log.info("Default DataSource initialized and cached for key: {}", this.defaultTenantKey);
        } else {
            log.warn("No default DataSource provided during initialization.");
        }
         // Call parent's afterPropertiesSet AFTER the default is potentially set
         super.afterPropertiesSet();
    }

    @Override
    @Nullable
    protected Object determineCurrentLookupKey() {
        String tenantId = TenantContext.getCurrentTenant();
        // If tenantId is null or matches the default key, return the default key
        if (tenantId == null || tenantId.equals(this.defaultTenantKey)) {
             log.debug("Tenant context is null or default key, using default lookup key: {}", this.defaultTenantKey);
             return this.defaultTenantKey;
        }
        log.debug("Determining DataSource for tenant: {}", tenantId);
        return tenantId; // Use the actual tenant ID as the key
    }

    @Override
    protected DataSource determineTargetDataSource() {
        Object lookupKey = determineCurrentLookupKey();
        Objects.requireNonNull(lookupKey, "DataSource lookup key cannot be null");

        // 1. Check cache first
        DataSource dataSource = resolvedDataSources.get(lookupKey);
        if (dataSource != null) {
            log.debug("Found cached DataSource for key: {}", lookupKey);
            return dataSource;
        }

        // 2. If it's the default key and it wasn't in the cache (shouldn't happen if initialized properly)
        if (lookupKey.equals(this.defaultTenantKey)) {
             log.error("Default DataSource (key: {}) not found in cache during lookup. This indicates an initialization issue.", lookupKey);
             // Attempt to retrieve from parent just in case, though it relies on the same cache internally
             DataSource defaultDs = super.determineTargetDataSource();
             if (defaultDs == null) {
                 throw new IllegalStateException("Default DataSource is missing.");
             }
             log.warn("Retrieved default DataSource via parent lookup.");
             resolvedDataSources.putIfAbsent(lookupKey, defaultDs); // Re-cache if missing
             return defaultDs;
        }

        // 3. If it's a specific tenant key and not in cache, try to create it
        log.info("DataSource for tenant key '{}' not found in cache. Attempting to create on demand.", lookupKey);
        // Use double-checked locking for thread-safe lazy initialization
        synchronized (this.lock) {
            // Re-check cache inside synchronized block
            dataSource = resolvedDataSources.get(lookupKey);
            if (dataSource != null) {
                log.debug("Found cached DataSource for key '{}' after acquiring lock.", lookupKey);
                return dataSource;
            }

            // Fetch configuration for the tenant
            TenantDataSourceProperties props = tenantConfigService.findByTenantId(lookupKey.toString());
            if (props == null) {
                // Configuration not found for this tenant ID
                log.error("Configuration not found for tenant ID: {}. Cannot create DataSource.", lookupKey);
                // Option 1: Throw exception (recommended to signal config error)
                throw new TenantDataSourceNotFoundException("Configuration not found for tenant: " + lookupKey);
                // Option 2: Fallback to default (can hide config errors)
                // log.warn("Falling back to default DataSource for tenant key: {}", lookupKey);
                // return (DataSource) getDefaultTargetDataSource();
            }

            // Create and cache the new DataSource
            try {
                log.info("Creating new DataSource for tenant key: {}", lookupKey);
                DataSource newDataSource = DataSourceConfig.createDataSource(
                    props.url, props.username, props.password, props.driverClassName
                );
                resolvedDataSources.put(lookupKey, newDataSource);
                log.info("Successfully created and cached DataSource for tenant key: {}", lookupKey);
                return newDataSource;
            } catch (Exception e) {
                log.error("Failed to create DataSource for tenant key: {}", lookupKey, e);
                throw new TenantDataSourceCreationException("Failed to create DataSource for tenant: " + lookupKey, e);
            }
        }
    }

     /**
     * Retrieves the map of currently resolved (cached) DataSources.
     * @return A map of tenant IDs to DataSource instances.
     */
    public Map<Object, DataSource> getResolvedDataSources() {
        return this.resolvedDataSources;
    }
}

// --- Custom Exceptions ---
class TenantDataSourceNotFoundException extends RuntimeException {
    public TenantDataSourceNotFoundException(String message) {
        super(message);
    }
}

class TenantDataSourceCreationException extends RuntimeException {
    public TenantDataSourceCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}


// --- 4. DataSource Configuration ---
// Simplified to configure only the default DataSource initially.
@Configuration
class DataSourceConfig {

    private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);

    // Default tenant configuration (load from external source ideally)
    private final String defaultTenantId = "default_tenant"; // Key used to identify the default DS
    private final String defaultDbUrl = "jdbc:h2:mem:defaultdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE";
    private final String defaultDbUsername = "sa";
    private final String defaultDbPassword = "";
    private final String defaultDbDriver = "org.h2.Driver";

    @Autowired // Inject the service that provides tenant configs
    private TenantConfigService tenantConfigService;

    // Creates the primary DataSource bean (the routing DataSource).
    @Bean(name = "dataSource")
    public DataSource dataSource() {
        log.info("Creating MultitenantDataSource bean...");

        // Create the router, passing the config service and default key
        MultitenantDataSource routingDataSource = new MultitenantDataSource(tenantConfigService, defaultTenantId);

        // Create ONLY the default DataSource instance here
        DataSource defaultDataSource = createDataSource(
            defaultDbUrl, defaultDbUsername, defaultDbPassword, defaultDbDriver
        );
        log.info("Default DataSource instance created.");

        // Initialize the router with the default DataSource
        routingDataSource.initializeDefaultDataSource(defaultDataSource);

        // No targetDataSources map is set here initially for tenants.
        // afterPropertiesSet() is called internally by initializeDefaultDataSource -> super.afterPropertiesSet()

        log.info("Multitenant DataSource configured with default only. Tenant DataSources will be created on demand.");
        return routingDataSource;
    }

    // Static helper method to create a DataSource instance. Remains public static.
    public static DataSource createDataSource(String url, String username, String password, String driverClassName) {
         if (url == null || url.trim().isEmpty()) {
            log.error("Database URL is null or empty. Cannot create DataSource.");
            throw new IllegalArgumentException("Database URL cannot be null or empty.");
        }
         log.info("Creating DataSource instance for URL: {}", url.substring(0, Math.min(url.length(), 50)) + "...");
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
// Registers the TenantInterceptor. Needs the default tenant ID.
@Configuration
class WebMvcConfig implements WebMvcConfigurer {

    private static final Logger log = LoggerFactory.getLogger(WebMvcConfig.class);
    // Ideally, inject this from properties or DataSourceConfig
    private final String defaultTenantId = "default_tenant";

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("Registering TenantInterceptor with default key: {}", defaultTenantId);
        registry.addInterceptor(new TenantInterceptor(defaultTenantId));
    }
}


// --- Example Usage (Service/Repository - No changes needed) ---
/*
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import javax.sql.DataSource; // Make sure this is javax.sql.DataSource

@Service
class MyTenantAwareService {

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public MyTenantAwareService(DataSource dataSource) { // Injects the MultitenantDataSource bean
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public String getDataFromTenantDb() {
        String currentTenant = TenantContext.getCurrentTenant();
        log.info("Executing query against tenant context: {}", currentTenant);
        // The jdbcTemplate will request a connection from the MultitenantDataSource,
        // which will either return a cached DS or create one on demand.
        try {
             // Example query (adjust for your DB, e.g., current_database() for PostgreSQL)
             return jdbcTemplate.queryForObject("SELECT 'Data from ' || DATABASE();", String.class);
        } catch (Exception e) {
            log.error("Error executing query for tenant context {}: {}", currentTenant, e.getMessage());
            // Handle specific exceptions like TenantDataSourceNotFoundException if needed
            if (e.getCause() instanceof TenantDataSourceNotFoundException) {
                 return "Error: Configuration not found for tenant " + currentTenant;
            }
            return "Error fetching data for tenant " + currentTenant;
        }
    }
}

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest; // Make sure this is jakarta

@RestController
class MyController {

    @Autowired
    private MyTenantAwareService myTenantAwareService;

    @GetMapping("/data")
    public String getTenantData(HttpServletRequest request) {
         String host = request.getServerName();
         String data = myTenantAwareService.getDataFromTenantDb();
         return "Request from host: " + host + " | " + data;
    }
}
*/

// --- Notes ---
// 1. **TenantConfigService Implementation**: The placeholder logic in `TenantConfigService` MUST be replaced to fetch configurations from your actual storage (database, file, etc.).
// 2. **Error Handling**: The code now throws `TenantDataSourceNotFoundException` if configuration is missing and `TenantDataSourceCreationException` if DataSource creation fails. Your application (e.g., services, controllers, or exception handlers) should handle these appropriately. Falling back to the default DataSource when a tenant config is missing might hide problems.
// 3. **Configuration Persistence**: If you allow dynamic updates to tenant configurations (e.g., via `TenantConfigService.addOrUpdateTenantConfig`), ensure those changes are persisted to your external store.
// 4. **Connection Pooling**: Ensure `createDataSource` configures connection pooling (like HikariCP) correctly. Each tenant will get its own pool, created on demand.
// 5. **Thread Safety**: Double-checked locking is used in `determineTargetDataSource` for thread-safe lazy initialization of DataSources.
// 6. **Default Tenant Key**: The `defaultTenantId` ("default_tenant" in this example) is used both in the interceptor fallback and as the key for the default DataSource in the cache. Ensure consistency.
