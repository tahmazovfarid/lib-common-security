package az.ailab.lib.common.security.provider;

import az.ailab.lib.common.security.model.TokenPayload;
import az.ailab.lib.common.security.model.UserPrincipal;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class UserTokenProvider extends AbstractTokenProvider {

    public UserTokenProvider(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    public Authentication buildAuthentication(TokenPayload tokenPayload) {
        List<GrantedAuthority> authorities = mapGrantedAuthorities(tokenPayload.getRoleName(), tokenPayload.getPermissions());
        UserPrincipal userPrincipal = UserPrincipal.of(tokenPayload, authorities);

        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                "",
                authorities
        );
    }

}
