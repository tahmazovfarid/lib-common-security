package az.ailab.lib.common.security.provider;

import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.security.model.TokenPayload;
import az.ailab.lib.common.security.util.JwtUtil;
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

/**
 * Abstract base for token-based authentication providers.
 * <p>
 * Provides common logic to extract and parse a JWT payload into a {@link TokenPayload} instance,
 * and to map claims into Spring Security authorities. Concrete subclasses must implement how
 * to build an {@link Authentication} object from the parsed payload.</p>
 *
 * @author tahmazovfarid
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractTokenProvider {

    /**
     * Shared Jackson {@link ObjectMapper} for JSON processing of token payloads.
     */
    private final ObjectMapper objectMapper;

    /**
     * Extracts and parses a JWT payload without verifying signature.
     * <p>
     * Decodes the Base64Url payload section, converts it to a JSON tree, and
     * maps it into a {@link TokenPayload} object.
     * </p>
     *
     * @param token the compact JWT string (header.payload.signature)
     * @return an {@link Optional} containing the {@link TokenPayload} if parsing succeeds,
     *         or {@link Optional#empty()} if JSON processing fails
     */
    public Optional<TokenPayload> extractPayload(final String token) {
        try {
            final String payloadJson = JwtUtil.decodePayloadNoVerify(token);
            final JsonNode payloadNode = objectMapper.readTree(payloadJson);
            return Optional.of(TokenPayload.fromJsonNode(payloadNode));
        } catch (JsonProcessingException ex) {
            log.error("Error processing payload JSON, message: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Builds a Spring Security {@link Authentication} object from the given token payload.
     * <p>
     * Subclasses should extract user details and authorities and return an appropriate
     * {@link Authentication} implementation (e.g. {@code UsernamePasswordAuthenticationToken}).
     * </p>
     *
     * @param tokenPayload the parsed JWT payload containing claims and nested user info
     * @return a populated {@link Authentication} instance representing the authenticated principal
     */
    public abstract Authentication buildAuthentication(final TokenPayload tokenPayload);

    /**
     * Maps a role and permission entries into a list of Spring Security authorities.
     * <p>
     * Prepends a standard prefix to the role name, then adds each permission key as its
     * own {@link SimpleGrantedAuthority}.</p>
     *
     * @param roleType the primary role type (without prefix)
     * @param permissions a map of permission identifiers to values (values are ignored here)
     * @return a list of {@link GrantedAuthority} including the role and each permission
     */
    public List<GrantedAuthority> mapGrantedAuthorities(
            final String roleType,
            final Map<String, String> permissions) {
        final List<GrantedAuthority> authorities = new ArrayList<>();
        // Add the role with configured prefix
        authorities.add(new SimpleGrantedAuthority(SecurityConstant.ROLE_PREFIX + roleType));
        // Add each permission as a separate authority
        permissions.keySet().stream()
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);
        return authorities;
    }

}
