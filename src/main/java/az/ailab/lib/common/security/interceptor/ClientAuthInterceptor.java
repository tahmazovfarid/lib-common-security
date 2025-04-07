package az.ailab.lib.common.security.interceptor;

import az.ailab.lib.common.security.config.annotation.ClientAuth;
import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.security.util.SecurityUtil;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import io.micrometer.common.util.StringUtils;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;

@Slf4j
@RequiredArgsConstructor
public class ClientAuthInterceptor implements RequestInterceptor {

    private final String srcServiceName;
    private final Map<String, String> clientApiKeys;

    @Override
    public void apply(final RequestTemplate template) {
        final Optional<ClientAuth> authAnnotation = getEffectiveAuthAnnotation(template);

        if (authAnnotation.isEmpty() || !authAnnotation.get().enabled()) {
            return;
        }

        final ClientAuth auth = authAnnotation.get();

        final String targetClientName = getTargetClientName(template, auth);

        addApiKeyToHeader(template, targetClientName);

        forwardAuthorizationHeader(template, auth);
    }

    private Optional<ClientAuth> getEffectiveAuthAnnotation(final RequestTemplate template) {
        final Method method = template.methodMetadata().method();
        final Class<?> declaringClass = method.getDeclaringClass();

        final ClientAuth methodAuth = method.getAnnotation(ClientAuth.class);
        final ClientAuth classAuth = declaringClass.getAnnotation(ClientAuth.class);

        return Optional.ofNullable(methodAuth != null ? methodAuth : classAuth);
    }

    private String getTargetClientName(final RequestTemplate template, final ClientAuth auth) {
        final String clientName = auth.clientName();
        return StringUtils.isNotBlank(clientName) ? clientName : template.feignTarget().name();
    }

    private void addApiKeyToHeader(final RequestTemplate template, final String targetClientName) {
        final String apiKey = clientApiKeys.get(targetClientName);
        if (apiKey != null) {
            template.header(SecurityConstant.X_SERVICE_NAME, srcServiceName);
            template.header(SecurityConstant.X_Client_API_KEY, apiKey);
        } else {
            log.warn("API key not found for client '{}'. Please check your configuration for clients.security.api-keys.{}",
                    targetClientName, targetClientName);
        }
    }

    private void forwardAuthorizationHeader(final RequestTemplate template, final ClientAuth auth) {
        if (auth.forwardAuthorizationHeader()) {
            SecurityUtil.getAuthorizationHeaderOpt()
                    .ifPresent(bearerToken -> template.header(HttpHeaders.AUTHORIZATION, bearerToken));
        }
    }

}