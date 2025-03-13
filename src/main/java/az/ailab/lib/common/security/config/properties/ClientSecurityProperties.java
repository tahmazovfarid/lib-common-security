package az.ailab.lib.common.security.config.properties;

import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "clients.security")
public class ClientSecurityProperties {

    private Map<String, String> apiKeys = new HashMap<>();

}
