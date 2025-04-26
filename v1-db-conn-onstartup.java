import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.net.URI;
import java.net.URISyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// --- 1. Tenant Context ---
// Holds the current tenant identifier in a ThreadLocal variable.
// This ensures that the tenant ID is specific to the current request thread.
class TenantContext {

    private static final Logger log = LoggerFactory.getLogger(TenantContext.class);
    // ThreadLocal storage for the tenant identifier (e.g., domain name)
    private static final ThreadLocal<String> currentTenant = new ThreadLocal<>();

    public static void setCurrentTenant(String tenantId) {
        log.debug("Setting tenant to: {}", tenantId);
        currentTenant.set(tenantId);
    }

    @Nullable // Indicate that the method might return null
    public static String getCurrentTenant() {
        return currentTenant.get();
    }

    public static void clear() {
        log.debug("Clearing tenant context");
        currentTenant.remove();
    }
}

// --- 2. Tenant Interceptor ---
// Intercepts incoming requests to determine and set the tenant identifier.
class TenantInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(TenantInterceptor.class);
    private final String defaultTenantId; // Fallback tenant

    public TenantInterceptor(String defaultTenantId) {
        this.defaultTenantId = defaultTenantId;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String tenantId = resolveTenantId(request);
        log.info("Request received for host: {}, Resolved Tenant ID: {}", request.getServerName(), tenantId);
        TenantContext.setCurrentTenant(tenantId);
        return true; // Continue processing the request
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        // Clear the tenant context after the request is complete (or if an error occurs)
        TenantContext.clear();
    }

    // Extracts the tenant identifier (domain) from the request.
    // You might need to adjust this logic based on how the domain is accessed (e.g., headers, server name).
    private String resolveTenantId(HttpServletRequest request) {
        // Example: Using the server name (host) as the tenant identifier
        String host = request.getServerName(); // e.g., "tenant1.example.com", "tenant2.yourapp.io"

        // Basic validation or mapping logic can go here.
        // For instance, you might only consider the subdomain part or map specific hosts.
        if (host != null && !host.isEmpty()) {
             // Simple example: use the full host name.
             // You could parse it further, e.g., extract "tenant1" from "tenant1.example.com"
             // String[] parts = host.split("\\.");
             // if (parts.length > 0) return parts[0];
            return host;
        }

        log.warn("Could not resolve tenant ID from host: {}. Falling back to default tenant: {}", host, defaultTenantId);
        // Fallback to a default tenant if the domain cannot be determined
        return defaultTenantId;
    }
}

// --- 3. Multi-Tenant DataSource Router ---
// Extends AbstractRoutingDataSource to route connections based on the tenant context.
class MultitenantDataSource extends AbstractRoutingDataSource {

    private static final Logger log = LoggerFactory.getLogger(MultitenantDataSource.class);

    // Determines which DataSource to use for the current request.
    @Override
    @Nullable
    protected Object determineCurrentLookupKey() {
        String tenantId = TenantContext.getCurrentTenant();
        log.debug("Determining DataSource for tenant: {}", tenantId);
        return tenantId; // The key used to look up the target DataSource
    }
}

// --- 4. DataSource Configuration ---
// Sets up the DataSource beans and the routing mechanism.
@Configuration
class DataSourceConfig {

    private static final Logger log = LoggerFactory.getLogger(DataSourceConfig.class);

    // Inject properties or load configuration for tenants here
    // For this example, we'll define them directly.
    // In a real app, load this from application.yml, a database, or a JSON file.

    // Define details for your default/fallback tenant
    private final String defaultTenantId = "default_tenant"; // A key for the default DB
    private final String defaultDbUrl = "jdbc:h2:mem:defaultdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE";
    private final String defaultDbUsername = "sa";
    private final String defaultDbPassword = "";
    private final String defaultDbDriver = "org.h2.Driver";

    // Define details for other tenants
    // Structure: Map<TenantId, Map<PropertyKey, PropertyValue>>
    private Map<String, Map<String, String>> tenantDatabases = new HashMap<>();

    public DataSourceConfig() {
        // --- Tenant Configuration Loading ---
        // **Replace this static configuration with your dynamic loading mechanism**
        // Option A: Load from application.yml (requires configuration properties binding)
        // Option B: Load from a dedicated configuration database
        // Option C: Load from a JSON/YAML file

        // Example: Static configuration
        Map<String, String> tenant1Props = new HashMap<>();
        tenant1Props.put("url", "jdbc:h2:mem:tenant1db;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
        tenant1Props.put("username", "sa");
        tenant1Props.put("password", "");
        tenant1Props.put("driverClassName", "org.h2.Driver");
        tenantDatabases.put("tenant1.example.com", tenant1Props); // Key matches resolved tenant ID

        Map<String, String> tenant2Props = new HashMap<>();
        tenant2Props.put("url", "jdbc:postgresql://localhost:5432/tenant2db");
        tenant2Props.put("username", "user2");
        tenant2Props.put("password", "pass2");
        tenant2Props.put("driverClassName", "org.postgresql.Driver");
        tenantDatabases.put("tenant2.yourapp.io", tenant2Props);

        log.info("Loaded configuration for tenants: {}", tenantDatabases.keySet());
        // --- End of Tenant Configuration Loading ---
    }


    // Creates the primary DataSource bean, which is the routing DataSource.
    @Bean(name = "dataSource") // Ensure this is the primary DataSource
    public DataSource dataSource() {
        MultitenantDataSource routingDataSource = new MultitenantDataSource();

        // Map to store the actual resolved DataSource objects
        Map<Object, Object> targetDataSources = new HashMap<>();

        // 1. Create and add the default DataSource
        DataSource defaultDataSource = createDataSource(
            defaultDbUrl, defaultDbUsername, defaultDbPassword, defaultDbDriver
        );
        targetDataSources.put(defaultTenantId, defaultDataSource);
        log.info("Configured default DataSource for tenant key: {}", defaultTenantId);

        // 2. Create and add DataSources for each configured tenant
        tenantDatabases.forEach((tenantId, properties) -> {
            DataSource tenantDataSource = createDataSource(
                properties.get("url"),
                properties.get("username"),
                properties.get("password"),
                properties.get("driverClassName")
            );
            targetDataSources.put(tenantId, tenantDataSource);
            log.info("Configured DataSource for tenant key: {}", tenantId);
        });

        // Set the resolved DataSources map on the routing DataSource
        routingDataSource.setTargetDataSources(targetDataSources);

        // Set the default DataSource to use when the tenant key is not found
        routingDataSource.setDefaultTargetDataSource(defaultDataSource);

        // Ensure internal initialization is complete
        routingDataSource.afterPropertiesSet();

        log.info("Multitenant DataSource configured with {} target(s) and default.", targetDataSources.size() -1 ); // -1 for default
        return routingDataSource;
    }

    // Helper method to create a DataSource instance.
    private DataSource createDataSource(String url, String username, String password, String driverClassName) {
         if (url == null || url.trim().isEmpty()) {
            log.error("Database URL is null or empty. Cannot create DataSource.");
            throw new IllegalArgumentException("Database URL cannot be null or empty.");
        }
         log.info("Creating DataSource for URL: {}", url.substring(0, Math.min(url.length(), 50)) + "..."); // Log URL safely
         DataSourceBuilder<?> dataSourceBuilder = DataSourceBuilder.create();
         dataSourceBuilder.driverClassName(driverClassName);
         dataSourceBuilder.url(url);
         dataSourceBuilder.username(username);
         dataSourceBuilder.password(password);
         // Add connection pool properties if needed (e.g., HikariCP)
         // dataSourceBuilder.type(HikariDataSource.class); // Example for HikariCP
         // Add properties like maximumPoolSize, connectionTimeout etc.
         return dataSourceBuilder.build();
    }
}

// --- 5. Web MVC Configuration ---
// Registers the TenantInterceptor.
@Configuration
class WebMvcConfig implements WebMvcConfigurer {

    // Inject the default tenant ID defined in DataSourceConfig (or from properties)
    // For simplicity, reusing the hardcoded value here, but ideally inject it.
    private final String defaultTenantId = "default_tenant";

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        log.info("Registering TenantInterceptor");
        // Register the interceptor to apply to all incoming requests
        registry.addInterceptor(new TenantInterceptor(defaultTenantId));
    }
}

// --- Example Usage (in a Service or Repository) ---
/*
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
class MyTenantAwareService {

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public MyTenantAwareService(DataSource dataSource) {
        // Inject the primary (routing) DataSource
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    public String getDataFromTenantDb() {
        // Spring automatically uses the DataSource resolved by MultitenantDataSource
        // based on the TenantContext set by the interceptor for this request thread.
        String currentTenant = TenantContext.getCurrentTenant(); // Optional: Log or use tenant info
        System.out.println("Executing query against tenant: " + currentTenant);

        // Example query
        try {
             return jdbcTemplate.queryForObject("SELECT 'Data from ' || DATABASE();", String.class); // H2 specific example
             // For PostgreSQL: SELECT 'Data from ' || current_database();
        } catch (Exception e) {
            System.err.println("Error executing query for tenant " + currentTenant + ": " + e.getMessage());
            return "Error fetching data";
        }
    }
}

// --- Example Controller ---

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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
// 1. Dependencies: Ensure you have `spring-boot-starter-web` and `spring-boot-starter-jdbc` (or `spring-boot-starter-data-jpa`). Add drivers for your databases (e.g., `h2`, `postgresql`).
// 2. Tenant Configuration: Replace the static map in `DataSourceConfig` with your preferred loading mechanism (e.g., reading from `application.yml` using `@ConfigurationProperties`, querying a central config DB at startup, or reading a JSON file).
// 3. Error Handling: Add more robust error handling, especially around tenant resolution and DataSource creation.
// 4. Security: Ensure database credentials are handled securely (e.g., using Spring Cloud Config Server, environment variables, or secrets management tools). Do not hardcode them directly in the source code for production.
// 5. JPA/Hibernate: If using JPA, Hibernate has built-in multi-tenancy support (DATABASE, SCHEMA, DISCRIMINATOR strategies) which might integrate differently but can still leverage a similar `AbstractRoutingDataSource` or Hibernate's `CurrentTenantIdentifierResolver`. The core concept of identifying the tenant per request remains the same.
// 6. Connection Pooling: For production, configure a robust connection pool (like HikariCP) for each tenant DataSource for performance and resource management. The `createDataSource` method can be updated accordingly.
// 7. Domain Resolution: The `resolveTenantId` logic in `TenantInterceptor` might need refinement based on your exact domain structure (e.g., subdomains, custom headers).
