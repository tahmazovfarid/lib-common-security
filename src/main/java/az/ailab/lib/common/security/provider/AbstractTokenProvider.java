package az.ailab.lib.common.security.provider;

import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.security.model.TokenPayload;
import az.ailab.lib.common.security.util.SecurityUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Slf4j
@RequiredArgsConstructor
public abstract class AbstractTokenProvider {

    private final ObjectMapper objectMapper;

    public Optional<TokenPayload> extractPayload(final String token) {
        try {
            final String payloadJson = SecurityUtil.extractPayload(token);
            final JsonNode payloadNode = objectMapper.readTree(payloadJson);
            return Optional.of(TokenPayload.fromJsonNode(payloadNode));
        } catch (JsonProcessingException ex) {
            log.error("Error processing payload json, message: {}", ex.getMessage());
        }

        return Optional.empty();
    }

    public abstract Authentication buildAuthentication(final TokenPayload tokenPayload);

    public List<GrantedAuthority> mapGrantedAuthorities(final String role,
                                                        final Map<String, String> permissions) {
        final List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(SecurityConstant.ROLE_PREFIX + role));

        authorities.addAll(permissions.keySet().stream()
                .map(SimpleGrantedAuthority::new).toList());

        return authorities;
    }

}
