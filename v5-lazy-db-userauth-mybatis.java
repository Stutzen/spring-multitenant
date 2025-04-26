import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.ModelAndView;

// --- MyBatis Imports ---
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.mybatis.spring.annotation.MapperScan; // To scan for mappers

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

// --- 3. Tenant Configuration Service ---
// (No changes needed - still uses default DataSource with JdbcTemplate for config/auth)
@Service
class TenantConfigService {
    private static final Logger log = LoggerFactory.getLogger(TenantConfigService.class);
    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public TenantConfigService(@Qualifier("defaultDataSource") DataSource defaultDataSource) {
        this.jdbcTemplate = new JdbcTemplate(defaultDataSource);
        log.info("TenantConfigService initialized with default DataSource.");
    }

    private static final RowMapper<TenantDataSourceProperties> tenantPropsMapper = (rs, rowNum) -> new TenantDataSourceProperties(
            rs.getString("db_url"), rs.getString("db_username"), rs.getString("db_password"), rs.getString("driver_class")
    );

    @Nullable
    public TenantDataSourceProperties findByTenantId(String tenantId) {
        log.debug("Fetching configuration for tenant ID: {}", tenantId);
        String sql = "SELECT db_url, db_username, db_password, driver_class FROM tenant_configs WHERE tenant_id = ?";
        try {
            return jdbcTemplate.queryForObject(sql, tenantPropsMapper, tenantId);
        } catch (EmptyResultDataAccessException e) {
            log.warn("No configuration found in central DB for tenant ID: {}", tenantId); return null;
        } catch (Exception e) {
            log.error("Error fetching configuration for tenant ID: {}", tenantId, e); return null;
        }
    }

    public boolean isUserAuthorizedForTenant(String userId, String tenantId) {
        if (userId == null || tenantId == null) { log.warn("Cannot check authorization with null userId or tenantId."); return false; }
        log.debug("Checking authorization for user '{}' on tenant '{}'", userId, tenantId);
        String sql = "SELECT COUNT(*) FROM user_tenant_mappings WHERE user_id = ? AND tenant_id = ?";
        try {
            Integer count = jdbcTemplate.queryForObject(sql, Integer.class, userId, tenantId);
            boolean authorized = count != null && count > 0;
            log.debug("Authorization result for user '{}' on tenant '{}': {}", userId, tenantId, authorized);
            return authorized;
        } catch (Exception e) {
            log.error("Error checking authorization for user '{}' on tenant '{}'", userId, tenantId, e); return false;
        }
    }
}

// --- Helper Class for Tenant Properties ---
// (No changes needed)
class TenantDataSourceProperties {
    final String url; final String username; final String password; final String driverClassName;
    public TenantDataSourceProperties(String url, String username, String password, String driverClassName) {
        this.url = url; this.username = username; this.password = password; this.driverClassName = driverClassName;
    }
}


// --- 4. Multi-Tenant DataSource Router ---
// (No changes needed - MyBatis uses this DataSource)
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
        if (dataSource != null) { log.trace("Found cached DataSource for key: {}", lookupKey); return dataSource; }

        if (lookupKey.equals(this.defaultTenantKey)) {
             log.error("Default DataSource (key: {}) not found in cache during lookup. Initialization issue?", lookupKey);
             DataSource defaultDs = (DataSource) getDefaultTargetDataSource();
             if (defaultDs == null) { throw new IllegalStateException("Default DataSource is missing."); }
             log.warn("Retrieved default DataSource via parent lookup.");
             resolvedDataSources.putIfAbsent(lookupKey, defaultDs);
             return defaultDs;
        }

        log.info("DataSource for tenant key '{}' not found in cache. Attempting creation.", lookupKey);
        synchronized (this.lock) {
            dataSource = resolvedDataSources.get(lookupKey);
            if (dataSource != null) { log.trace("Found cached DataSource for key '{}' after acquiring lock.", lookupKey); return dataSource; }

            TenantDataSourceProperties props = tenantConfigService.findByTenantId(lookupKey.toString());
            if (props == null) {
                log.error("Configuration not found for tenant ID: {}. Cannot create DataSource.", lookupKey);
                throw new TenantDataSourceNotFoundException("Configuration not found for tenant: " + lookupKey);
            }
            try {
                log.info("Creating new DataSource for tenant key: {}", lookupKey);
                DataSource newDataSource = DataSourceConfig.createDataSource(props.url, props.username, props.password, props.driverClassName);
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


// --- 5. DataSource and MyBatis Configuration ---
@Configuration
// Add @MapperScan to tell MyBatis where to find your mapper interfaces
@MapperScan("com.yourcompany.yourapp.mappers") // <-- ADJUST THIS PACKAGE NAME
class DataSourceConfig { // Renamed slightly for clarity, but could be separate classes
    private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);

    // ** Load these from application.properties/yml **
    private final String defaultTenantId = "default_tenant";
    private final String defaultDbUrl = "jdbc:postgresql://localhost:5432/central_config_db";
    private final String defaultDbUsername = "config_user";
    private final String defaultDbPassword = "config_password";
    private final String defaultDbDriver = "org.postgresql.Driver";

    @Autowired
    private TenantConfigService tenantConfigService;

    @Bean
    @Qualifier("defaultDataSource")
    public DataSource defaultDataSource() {
        log.info("Creating default DataSource bean (for central config)");
        return createDataSource(defaultDbUrl, defaultDbUsername, defaultDbPassword, defaultDbDriver);
    }

    @Bean
    @Primary // This ensures mybatis-spring-boot-starter picks up the routing DataSource
    public DataSource dataSource(@Qualifier("defaultDataSource") DataSource defaultDataSource) {
        log.info("Creating MultitenantDataSource bean (primary application DataSource)");
        MultitenantDataSource routingDataSource = new MultitenantDataSource(tenantConfigService, defaultTenantId);
        routingDataSource.initializeDefaultDataSource(defaultDataSource);
        log.info("Multitenant DataSource configured.");
        return routingDataSource;
    }

    // --- MyBatis Auto-Configuration ---
    // The mybatis-spring-boot-starter will automatically:
    // 1. Create an SqlSessionFactory using the @Primary DataSource (our MultitenantDataSource).
    // 2. Create an SqlSessionTemplate based on the SqlSessionFactory.
    // 3. Scan for mappers in the package specified by @MapperScan.
    // No explicit @Bean definitions for SqlSessionFactory or SqlSessionTemplate are usually needed.

    // Optional: Configure MyBatis properties via application.properties/yml
    // Example:
    // mybatis.mapper-locations=classpath*:mappers/**/*.xml
    // mybatis.configuration.map-underscore-to-camel-case=true

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
         return dataSourceBuilder.build();
    }
}

// --- 6. Web MVC Configuration ---
// (No changes needed - Interceptors remain the same)
@Configuration
class WebMvcConfig implements WebMvcConfigurer {
    private static final Logger log = LoggerFactory.getLogger(WebMvcConfig.class);
    @Autowired private TenantConfigService tenantConfigService;
    private final String defaultTenantId = "default_tenant"; // Inject from props

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("Registering interceptors...");
        registry.addInterceptor(new TenantInterceptor(defaultTenantId)).order(0).addPathPatterns("/**");
        log.info("Registered TenantInterceptor (order 0)");
        registry.addInterceptor(new TenantAuthorizationInterceptor(tenantConfigService, defaultTenantId))
                .order(1).addPathPatterns("/**").excludePathPatterns("/login", "/error", "/public/**");
        log.info("Registered TenantAuthorizationInterceptor (order 1)");
    }
}

// --- 7. Tenant Authorization Interceptor ---
// (No changes needed)
@Component
class TenantAuthorizationInterceptor implements HandlerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(TenantAuthorizationInterceptor.class);
    private final TenantConfigService tenantConfigService;
    private final String defaultTenantKey;

    public TenantAuthorizationInterceptor(TenantConfigService tenantConfigService, String defaultTenantKey) {
        this.tenantConfigService = tenantConfigService; this.defaultTenantKey = defaultTenantKey;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String tenantId = TenantContext.getCurrentTenant();
        if (tenantId == null) { log.warn("Authorization Check: TenantContext is null. Access denied."); throw new AccessDeniedException("Tenant context not established."); }
        if (defaultTenantKey.equals(tenantId)) { log.debug("Authorization Check: Skipping check for default tenant key '{}'", tenantId); return true; }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
             log.warn("Authorization Check: User not authenticated for tenant '{}'. Access denied.", tenantId); throw new AccessDeniedException("User not authenticated.");
        }
        String userId = authentication.getName();
        log.debug("Authorization Check: Checking access for user '{}' to tenant '{}'", userId, tenantId);
        boolean isAuthorized = tenantConfigService.isUserAuthorizedForTenant(userId, tenantId);
        if (!isAuthorized) { log.warn("Authorization Check: User '{}' is NOT authorized for tenant '{}'. Access denied.", userId, tenantId); throw new AccessDeniedException("User not authorized for tenant " + tenantId); }
        log.debug("Authorization Check: User '{}' is authorized for tenant '{}'. Proceeding.", userId, tenantId);
        return true;
    }
    // postHandle, afterCompletion omitted for brevity
}


// --- Example Usage with MyBatis ---

// 1. Define a Mapper Interface (Place in package specified by @MapperScan, e.g., com.yourcompany.yourapp.mappers)
@Mapper // Mark this interface as a MyBatis mapper
interface ExampleTenantDataMapper {

    // Example: Select some data from a table in the tenant's database
    // The SQL should be generic enough for all tenant DB schemas or use dynamic SQL if needed.
    // Assumes a table named 'tenant_data' with a 'value' column.
    @Select("SELECT value FROM tenant_data WHERE id = #{id}")
    String findDataById(int id);

    // Example: Get the current database name (specific to DB vendor)
    // Use appropriate function for your target databases (e.g., DATABASE() for H2/MySQL, current_database() for PostgreSQL)
    @Select("SELECT DATABASE()") // Adjust function based on your DB
    String getCurrentDatabaseName();
}

// 2. Use the Mapper in a Service
@Service
class MyTenantAwareService {
    private static final Logger log = LoggerFactory.getLogger(MyTenantAwareService.class);

    private final ExampleTenantDataMapper tenantDataMapper; // Inject the mapper

    @Autowired
    public MyTenantAwareService(ExampleTenantDataMapper tenantDataMapper) {
        this.tenantDataMapper = tenantDataMapper;
    }

    public String getDataFromTenantDb() {
        String currentTenant = TenantContext.getCurrentTenant(); // For logging/context
        log.info("Executing MyBatis query via mapper against tenant context: {}", currentTenant);

        // MyBatis automatically uses the SqlSessionTemplate configured with the
        // MultitenantDataSource. The routing DataSource selects the correct
        // underlying tenant DataSource based on TenantContext.
        try {
            // Call mapper methods as usual
            String dbName = tenantDataMapper.getCurrentDatabaseName();
            // String specificData = tenantDataMapper.findDataById(1); // Example data fetch
            return "Data from DB: " + dbName;
            // return "Data from DB: " + dbName + " | Specific Data: " + specificData;
        } catch (Exception e) {
            log.error("Error executing MyBatis query for tenant context {}: {}", currentTenant, e.getMessage());
            // Handle specific exceptions like TenantDataSourceNotFoundException if needed
            // Note: MyBatis might wrap DB exceptions, check e.getCause()
            Throwable cause = e.getCause();
            if (cause instanceof TenantDataSourceNotFoundException || cause instanceof TenantDataSourceCreationException) {
                 return "Error: Problem accessing database for tenant " + currentTenant + ". " + cause.getMessage();
            }
            return "Error fetching data via MyBatis for tenant " + currentTenant;
        }
    }
}

// 3. Controller remains the same
/*
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;

@RestController
class MyController {
    @Autowired private MyTenantAwareService myTenantAwareService;

    @GetMapping("/data")
    public String getTenantData(HttpServletRequest request) {
         String host = request.getServerName();
         String data = myTenantAwareService.getDataFromTenantDb();
         return "Request from host: " + host + " | " + data;
    }
}
*/

// --- Notes ---
// 1. **Dependencies**: Add `org.mybatis.spring.boot:mybatis-spring-boot-starter:<version>` to your build file.
// 2. **`@MapperScan`**: Ensure the package name in `@MapperScan` correctly points to where your mapper interfaces reside.
// 3. **MyBatis Configuration**: Customize MyBatis further using `application.properties` or `application.yml` (e.g., `mybatis.mapper-locations`, `mybatis.configuration.*`).
// 4. **SQL Dialects**: If tenant databases use different SQL dialects (e.g., H2 vs. PostgreSQL), use database vendor-neutral SQL where possible or MyBatis's dynamic SQL features (`<if>`, `<choose>`, databaseIdProvider) if necessary. The example `DATABASE()` function is specific.
// 5. **Transaction Management**: Spring Boot's transaction management (`@Transactional`) will work seamlessly with MyBatis and the routing DataSource. Annotate your service methods as needed.
// 6. **Central DB Operations**: The `TenantConfigService` continues to use `JdbcTemplate` for the central config DB. If you needed complex operations there, you could configure a separate `SqlSessionFactory` specifically for the `defaultDataSource`, but it's often simpler to keep using `JdbcTemplate` for configuration tasks.
