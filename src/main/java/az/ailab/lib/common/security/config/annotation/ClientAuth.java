package az.ailab.lib.common.security.config.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Specifies authentication requirements when making calls to client services.
 * This annotation can be applied to both Feign client interfaces and individual methods.
 * <p>Usage examples:</p>
 *
 * <pre><code>
 * // Apply to entire client interface - uses interface name as clientName by default
 * {@literal @}FeignClient(name = "organization-client")
 * {@literal @}ClientAuth(forwardAuthorizationHeader = true)
 *  public interface OrganizationClient {
 *     // Methods inherit the class-level settings
 *  }
 *
 * // Apply to specific methods - overrides class-level settings
 * {@literal @}FeignClient(name = "user-client")
 *  public interface UserClient {
 *     // No API key will be sent for this public endpoint
 *     {@literal @}ClientAuth(enabled = false)
 *     {@literal @}GetMapping("/public/health")
 *     HealthStatus getHealth();
 *
 *     // Send API key and forward user's JWT token
 *     {@literal @}ClientAuth(forwardAuthorizationHeader = true)
 *     {@literal @}GetMapping("/users/{id}")
 *     UserDto getUser({@literal @}PathVariable Long id);
 *
 *     // Specify a different client API key to use
 *     {@literal @}ClientAuth(clientName = "admin-service", forwardAuthorizationHeader = true)
 *     {@literal @}GetMapping("/admin/users")
 *     {@literal List<UserDto>} getUsersAsAdmin();
 *  }
 * </code></pre>
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ClientAuth {

    /**
     * Specifies which client API key to use when making the request.
     * <p>If not specified, defaults to the Feign client name. The value should match
     * a key in your application's {@code clients.security.api-keys} configuration.</p>
     *
     * @return the client name to use for API key lookup
     */
    String clientName() default "";

    /**
     * Controls whether service authentication headers should be sent.
     * <p>When {@code enabled=false}, no API key or service name headers will be added
     * to the request. This is useful for public endpoints that don't require authentication.</p>
     *
     * @return true to send service auth headers, false to skip them
     */
    boolean enabled() default true;

    /**
     * Controls whether the current user's Authorization header (JWT token) should
     * be forwarded to the target service.
     * <p>This is needed when the target service needs to know which user is making the
     * request, for example for authorization checks or audit purposes.</p>
     *
     * @return true to forward the Authorization header, false otherwise
     */
    boolean forwardAuthorizationHeader() default false;
}