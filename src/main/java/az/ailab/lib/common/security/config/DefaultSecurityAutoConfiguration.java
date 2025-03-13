package az.ailab.lib.common.security.config;

import az.ailab.lib.common.security.filter.JwtTokenFilter;
import az.ailab.lib.common.security.provider.UserTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@ConditionalOnClass({SecurityFilterChain.class})
public class DefaultSecurityAutoConfiguration {

    private static final String CONTENT_SECURITY_POLICY = "script-src 'self'";
    private static final String[] IGNORING_PATH = {
            "/v3/api-docs",
            "/swagger-ui/**",
            "/actuator/health"
    };

    private final UserTokenProvider userTokenProvider;

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(IGNORING_PATH).permitAll()
                        .anyRequest().authenticated()
                )

                .headers(headers -> headers
                        .contentSecurityPolicy(policy -> policy
                                .policyDirectives(CONTENT_SECURITY_POLICY)))

                .addFilterBefore(new JwtTokenFilter(userTokenProvider),
                        UsernamePasswordAuthenticationFilter.class)

                .build();
    }

}
