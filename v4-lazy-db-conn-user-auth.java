import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary; // To mark the routing datasource as primary
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier; // For qualifying the default datasource
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate; // For querying config DB
import org.springframework.jdbc.core.RowMapper; // For mapping results
import org.springframework.dao.EmptyResultDataAccessException; // To handle no results found
import org.springframework.security.access.AccessDeniedException; // For authorization failure
import org.springframework.security.core.Authentication; // To get current user
import org.springframework.security.core.context.SecurityContextHolder; // To get current user
import org.springframework.web.servlet.ModelAndView; // Added for Authorization Interceptor postHandle

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
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
        // Ensure default tenant ID is handled consistently if needed upstream
        // String effectiveTenantId = defaultTenantId.equals(tenantId) ? defaultTenantId : tenantId;
        log.info("TenantInterceptor: Request for host: {}, Resolved Tenant ID: {}", request.getServerName(), tenantId);
        TenantContext.setCurrentTenant(tenantId);
        return true;
    }
    @Override public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception { TenantContext.clear(); }
    private String resolveTenantId(HttpServletRequest request) {
        String host = request.getServerName();
        if (host != null && !host.isEmpty()) { return host; }
        log.warn("TenantInterceptor: Could not resolve tenant ID from host: {}. Falling back to default tenant: {}", host, defaultTenantId);
        return defaultTenantId;
    }
}

// --- NEW: Tenant Configuration Service ---
// Now uses the default DataSource to fetch configurations and check authorization.
@Service
class TenantConfigService {
    private static final Logger log = LoggerFactory.getLogger(TenantConfigService.class);

    private final JdbcTemplate jdbcTemplate; // Configured with the default DataSource

    // Inject the specifically qualified default DataSource
    @Autowired
    public TenantConfigService(@Qualifier("defaultDataSource") DataSource defaultDataSource) {
        this.jdbcTemplate = new JdbcTemplate(defaultDataSource);
        log.info("TenantConfigService initialized with default DataSource.");
    }

    // RowMapper for TenantDataSourceProperties
    private static final RowMapper<TenantDataSourceProperties> tenantPropsMapper = (rs, rowNum) -> new TenantDataSourceProperties(
            rs.getString("db_url"),
            rs.getString("db_username"),
            rs.getString("db_password"), // Be cautious about storing/retrieving raw passwords
            rs.getString("driver_class")
    );

    /**
     * Fetches the DataSource properties for a given tenant ID from the central config DB.
     *
     * @param tenantId The identifier of the tenant (e.g., subdomain).
     * @return TenantDataSourceProperties if found, otherwise null.
     */
    @Nullable
    public TenantDataSourceProperties findByTenantId(String tenantId) {
        log.debug("Fetching configuration for tenant ID: {}", tenantId);
        String sql = "SELECT db_url, db_username, db_password, driver_class FROM tenant_configs WHERE tenant_id = ?";
        try {
            return jdbcTemplate.queryForObject(sql, tenantPropsMapper, tenantId);
        } catch (EmptyResultDataAccessException e) {
            log.warn("No configuration found in central DB for tenant ID: {}", tenantId);
            return null;
        } catch (Exception e) {
            log.error("Error fetching configuration for tenant ID: {}", tenantId, e);
            // Depending on policy, you might want to re-throw a specific exception
            return null;
        }
    }

    /**
     * Checks if a user is authorized to access a specific tenant's data.
     * Queries the user_tenant_mappings table in the central config DB.
     *
     * @param userId   The identifier of the user (e.g., username from SecurityContext).
     * @param tenantId The identifier of the tenant (e.g., subdomain).
     * @return true if the user is mapped to the tenant, false otherwise.
     */
    public boolean isUserAuthorizedForTenant(String userId, String tenantId) {
        if (userId == null || tenantId == null) {
            log.warn("Cannot check authorization with null userId or tenantId.");
            return false;
        }
        log.debug("Checking authorization for user '{}' on tenant '{}'", userId, tenantId);
        // Use COUNT(*) for efficiency, we only need to know if a mapping exists.
        String sql = "SELECT COUNT(*) FROM user_tenant_mappings WHERE user_id = ? AND tenant_id = ?";
        try {
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, userId, tenantId);
            boolean authorized = count != null && count > 0;
            log.debug("Authorization result for user '{}' on tenant '{}': {}", userId, tenantId, authorized);
            return authorized;
        } catch (Exception e) {
            log.error("Error checking authorization for user '{}' on tenant '{}'", userId, tenantId, e);
            return false; // Fail securely
        }
    }

    // Optional: Method to add/update tenant configs dynamically if needed
    // public void addOrUpdateTenantConfig(String tenantId, TenantDataSourceProperties properties) { ... }
}

// --- Helper Class for Tenant Properties ---
// (No changes needed)
class TenantDataSourceProperties {
    final String url;
    final String username;
    final String password;
    final String driverClassName;
    public TenantDataSourceProperties(String url, String username, String password, String driverClassName) {
        this.url = url; this.username = username; this.password = password; this.driverClassName = driverClassName;
    }
}


// --- 3. Multi-Tenant DataSource Router ---
// (No significant changes needed in logic, relies on TenantConfigService)
class MultitenantDataSource extends AbstractRoutingDataSource {
    private static final Logger log = LoggerFactory.getLogger(MultitenantDataSource.class);
    private final Map<Object, DataSource> resolvedDataSources = new ConcurrentHashMap<>();
    private final Object lock = new Object();
    private final TenantConfigService tenantConfigService;
    private final String defaultTenantKey;

    public MultitenantDataSource(TenantConfigService tenantConfigService, String defaultTenantKey) {
        this.tenantConfigService = Objects.requireNonNull(tenantConfigService, "TenantConfigService cannot be null");
        this.defaultTenantKey = Objects.requireNonNull(defaultTenantKey, "Default Tenant Key cannot be null");
    }

    public void initializeDefaultDataSource(DataSource defaultDataSource) {
        if (defaultDataSource != null) {
            this.resolvedDataSources.put(this.defaultTenantKey, defaultDataSource);
            super.setDefaultTargetDataSource(defaultDataSource);
            log.info("Default DataSource initialized and cached for key: {}", this.defaultTenantKey);
        } else { log.warn("No default DataSource provided during initialization."); }
        super.afterPropertiesSet();
    }

    @Override @Nullable protected Object determineCurrentLookupKey() {
        String tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null || tenantId.equals(this.defaultTenantKey)) {
            log.debug("Tenant context is null or default key, using default lookup key: {}", this.defaultTenantKey);
            return this.defaultTenantKey;
        }
        log.debug("Determining DataSource for tenant: {}", tenantId);
        return tenantId;
    }

    @Override protected DataSource determineTargetDataSource() {
        Object lookupKey = determineCurrentLookupKey();
        Objects.requireNonNull(lookupKey, "DataSource lookup key cannot be null");

        DataSource dataSource = resolvedDataSources.get(lookupKey);
        if (dataSource != null) {
            log.trace("Found cached DataSource for key: {}", lookupKey); // Changed to trace for less noise
            return dataSource;
        }

        if (lookupKey.equals(this.defaultTenantKey)) {
             log.error("Default DataSource (key: {}) not found in cache during lookup. Initialization issue?", lookupKey);
             DataSource defaultDs = (DataSource) getDefaultTargetDataSource(); // Rely on parent's retrieval
             if (defaultDs == null) { throw new IllegalStateException("Default DataSource is missing."); }
             log.warn("Retrieved default DataSource via parent lookup.");
             resolvedDataSources.putIfAbsent(lookupKey, defaultDs);
             return defaultDs;
        }

        log.info("DataSource for tenant key '{}' not found in cache. Attempting creation.", lookupKey);
        synchronized (this.lock) {
            dataSource = resolvedDataSources.get(lookupKey); // Double-check
            if (dataSource != null) {
                log.trace("Found cached DataSource for key '{}' after acquiring lock.", lookupKey);
                return dataSource;
            }

            TenantDataSourceProperties props = tenantConfigService.findByTenantId(lookupKey.toString());
            if (props == null) {
                log.error("Configuration not found for tenant ID: {}. Cannot create DataSource.", lookupKey);
                throw new TenantDataSourceNotFoundException("Configuration not found for tenant: " + lookupKey);
            }

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
    public Map<Object, DataSource> getResolvedDataSources() { return this.resolvedDataSources; }
}

// --- Custom Exceptions ---
// (No changes needed)
class TenantDataSourceNotFoundException extends RuntimeException { public TenantDataSourceNotFoundException(String message) { super(message); } }
class TenantDataSourceCreationException extends RuntimeException { public TenantDataSourceCreationException(String message, Throwable cause) { super(message, cause); } }


// --- 4. DataSource Configuration ---
// Defines default DS with qualifier, injects it into TenantConfigService.
@Configuration
class DataSourceConfig {
    private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);

    // Default tenant configuration details
    // ** Load these from application.properties/yml in a real app **
    private final String defaultTenantId = "default_tenant";
    private final String defaultDbUrl = "jdbc:postgresql://localhost:5432/central_config_db"; // Example: Central config DB URL
    private final String defaultDbUsername = "config_user";
    private final String defaultDbPassword = "config_password";
    private final String defaultDbDriver = "org.postgresql.Driver";

    @Autowired
    private TenantConfigService tenantConfigService; // Still needed by MultitenantDataSource

    /**
     * Creates the DataSource bean for the default/central configuration database.
     * Marked with @Qualifier for specific injection elsewhere.
     */
    @Bean
    @Qualifier("defaultDataSource")
    public DataSource defaultDataSource() {
        log.info("Creating default DataSource bean (for central config)");
        return createDataSource(
            defaultDbUrl, defaultDbUsername, defaultDbPassword, defaultDbDriver
        );
    }

    /**
     * Creates the primary DataSource bean used by the application for tenant routing.
     * Marked @Primary so it's the default for injection unless qualified.
     */
    @Bean
    @Primary // Mark this as the primary DataSource for general injection
    public DataSource dataSource(@Qualifier("defaultDataSource") DataSource defaultDataSource) {
        log.info("Creating MultitenantDataSource bean (primary application DataSource)");
        MultitenantDataSource routingDataSource = new MultitenantDataSource(tenantConfigService, defaultTenantId);
        routingDataSource.initializeDefaultDataSource(defaultDataSource); // Initialize with the actual default DS bean
        log.info("Multitenant DataSource configured.");
        return routingDataSource;
    }

    // Static helper method to create a DataSource instance.
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
         // Configure connection pooling (e.g., HikariCP) here
         // dataSourceBuilder.type(com.zaxxer.hikari.HikariDataSource.class);
         return dataSourceBuilder.build();
    }
}

// --- 5. Web MVC Configuration ---
// Registers BOTH interceptors in the correct order.
@Configuration
class WebMvcConfig implements WebMvcConfigurer {
    private static final Logger log = LoggerFactory.getLogger(WebMvcConfig.class);

    @Autowired // Inject the service needed by the auth interceptor
    private TenantConfigService tenantConfigService;

    // Ideally, inject this from properties or DataSourceConfig
    private final String defaultTenantId = "default_tenant";

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("Registering interceptors...");

        // 1. TenantInterceptor runs first to set the tenant context
        registry.addInterceptor(new TenantInterceptor(defaultTenantId))
                .order(0) // Explicitly order it first
                .addPathPatterns("/**"); // Apply to all paths (adjust if needed)
        log.info("Registered TenantInterceptor (order 0)");

        // 2. TenantAuthorizationInterceptor runs second to check access
        registry.addInterceptor(new TenantAuthorizationInterceptor(tenantConfigService, defaultTenantId))
                .order(1) // Explicitly order it second
                .addPathPatterns("/**") // Apply to all paths
                .excludePathPatterns("/login", "/error", "/public/**"); // Exclude paths that don't require tenant auth
        log.info("Registered TenantAuthorizationInterceptor (order 1)");
    }
}

// --- 6. NEW: Tenant Authorization Interceptor ---
// Checks if the current user is allowed to access the current tenant.
@Component // Mark as component although we instantiate it manually in WebMvcConfig
class TenantAuthorizationInterceptor implements HandlerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(TenantAuthorizationInterceptor.class);

    private final TenantConfigService tenantConfigService;
    private final String defaultTenantKey;

    // Inject dependencies (can be @Autowired if managed by Spring, or passed via constructor)
    public TenantAuthorizationInterceptor(TenantConfigService tenantConfigService, String defaultTenantKey) {
        this.tenantConfigService = tenantConfigService;
        this.defaultTenantKey = defaultTenantKey;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String tenantId = TenantContext.getCurrentTenant();

        // If tenant context is not set (shouldn't happen if TenantInterceptor ran), deny access.
        if (tenantId == null) {
            log.warn("Authorization Check: TenantContext is null. Access denied.");
            throw new AccessDeniedException("Tenant context not established.");
        }

        // Don't check authorization for the default tenant context itself
        // (assuming default DB access is handled by standard security rules).
        // Adjust this logic if the default tenant also requires specific user mapping.
        if (defaultTenantKey.equals(tenantId)) {
            log.debug("Authorization Check: Skipping check for default tenant key '{}'", tenantId);
            return true;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // If user is not authenticated, deny access (Spring Security might handle this earlier)
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
             log.warn("Authorization Check: User not authenticated for tenant '{}'. Access denied.", tenantId);
             throw new AccessDeniedException("User not authenticated.");
        }

        String userId = authentication.getName(); // Get username or principal ID

        log.debug("Authorization Check: Checking access for user '{}' to tenant '{}'", userId, tenantId);

        // Perform the authorization check using the service
        boolean isAuthorized = tenantConfigService.isUserAuthorizedForTenant(userId, tenantId);

        if (!isAuthorized) {
            log.warn("Authorization Check: User '{}' is NOT authorized for tenant '{}'. Access denied.", userId, tenantId);
            throw new AccessDeniedException("User not authorized for tenant " + tenantId);
        }

        log.debug("Authorization Check: User '{}' is authorized for tenant '{}'. Proceeding.", userId, tenantId);
        return true; // User is authorized, continue request processing
    }

     // Optional: Implement postHandle and afterCompletion if needed, but often not required for pure auth checks.
     @Override
     public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
         // Runs after the handler method but before the view is rendered.
     }

     @Override
     public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
         // Runs after the complete request has finished, including view rendering.
         // Useful for cleanup, but TenantContext cleanup is handled by TenantInterceptor.
     }
}


// --- Example Usage (Service/Repository - No changes needed in structure) ---
/*
@Service
class MyTenantAwareService {
    // ... (JdbcTemplate injected with primary MultitenantDataSource)
    // ... getDataFromTenantDb() method remains the same
    // Authorization is handled *before* this service method is called by the interceptor.
}

@RestController
class MyController {
    // ... (Injects MyTenantAwareService)
    // ... getTenantData() method remains the same
}
*/
