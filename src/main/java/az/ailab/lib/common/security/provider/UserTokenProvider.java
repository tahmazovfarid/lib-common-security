package az.ailab.lib.common.security.provider;

import az.ailab.lib.common.security.model.TokenPayload;
import az.ailab.lib.common.security.model.UserPrincipal;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Concrete implementation of {@link AbstractTokenProvider} for standard user tokens.
 * <p>
 * Parses claim data into a {@link UserPrincipal} and wraps it in a
 * {@link UsernamePasswordAuthenticationToken} along with mapped authorities.
 * </p>
 *
 * @author tahmazovfarid
 * @since 1.0
 */
@Component
public class UserTokenProvider extends AbstractTokenProvider {

    /**
     * Constructs the provider with a configured Jackson {@link ObjectMapper} for
     * JSON-to-POJO payload extraction.
     *
     * @param objectMapper the shared ObjectMapper bean
     */
    public UserTokenProvider(final ObjectMapper objectMapper) {
        super(objectMapper);
    }

    /**
     * Builds a Spring Security {@link Authentication} token from the provided JWT payload.
     * <p>
     * Creates a {@link UserPrincipal} containing user details and roles,
     * then returns a {@link UsernamePasswordAuthenticationToken} with these authorities.
     * </p>
     *
     * @param tokenPayload the parsed JWT payload with user, role, and permission data
     * @return an {@link Authentication} instance ready for authentication context
     */
    @Override
    public Authentication buildAuthentication(final TokenPayload tokenPayload) {
        final List<GrantedAuthority> authorities = mapGrantedAuthorities(
                tokenPayload.getUserType(),
                tokenPayload.getRoleType(),
                tokenPayload.getPermissions()
        );
        final UserPrincipal userPrincipal = UserPrincipal.of(tokenPayload, authorities);

        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                "",
                authorities
        );
    }

}