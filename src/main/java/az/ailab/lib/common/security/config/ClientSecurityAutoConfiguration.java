package az.ailab.lib.common.security.config;

import az.ailab.lib.common.security.config.properties.ClientSecurityProperties;
import az.ailab.lib.common.security.interceptor.ClientAuthInterceptor;
import feign.RequestInterceptor;
import java.util.Collections;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(ClientSecurityProperties.class)
@ConditionalOnClass(name = "feign.RequestInterceptor")
@ConditionalOnProperty(prefix = "clients.security", name = "enabled", havingValue = "true")
public class ClientSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public RequestInterceptor serviceAuthInterceptor(
            @Value("${spring.application.name}") String srcServiceName,
            ClientSecurityProperties properties) {
        Map<String, String> clientApiKeys = properties.getApiKeys() != null ?
                properties.getApiKeys() : Collections.emptyMap();

        return new ClientAuthInterceptor(srcServiceName, clientApiKeys);
    }

}
