package az.ailab.lib.common.security.config.annotation;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import az.ailab.lib.common.security.config.DefaultSecurityAutoConfiguration;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

/**
 * Enables default security configuration for microservices.
 * <p>To override the default configuration, define your own bean:</p>
 * <pre>
 * {@code
 * @Bean
 * public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
 *     return http
 *         // Your custom configuration
 *         .build();
 * }
 * }
 * </pre>
 */
@Target(TYPE)
@Retention(RUNTIME)
@Documented
@Import(DefaultSecurityAutoConfiguration.class)
public @interface EnableDefaultSecurity {

}
