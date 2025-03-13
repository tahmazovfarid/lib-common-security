package az.ailab.lib.common.security.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.security.contant.TestConstant;
import az.ailab.lib.common.security.model.TokenPayload;
import az.ailab.lib.common.security.model.UserPrincipal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@ExtendWith(MockitoExtension.class)
public class UserTokenProviderTest {

    @InjectMocks
    private UserTokenProvider userTokenProvider;

    @Test
    void testBuildAuthentication() {
        String roleName = TestConstant.ADMIN;
        Set<String> permissions = new HashSet<>(Set.of(TestConstant.USER_READ, TestConstant.USER_WRITE));

        TokenPayload tokenPayload = mock(TokenPayload.class);
        when(tokenPayload.getRoleName()).thenReturn(roleName);
        when(tokenPayload.getPermissions()).thenReturn(permissions);

        Authentication authentication = userTokenProvider.buildAuthentication(tokenPayload);

        assertThat(authentication).isNotNull();

        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);

        assertThat(authentication.getPrincipal()).isInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        assertThat(tokenPayload).isEqualTo(userPrincipal.getPayload());

        List<GrantedAuthority> authorities = new ArrayList<>(authentication.getAuthorities());
        assertThat(authorities).isNotNull();

        assertThat(authorities.size()).isEqualTo(3);

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .contains(SecurityConstant.ROLE_PREFIX + roleName);

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .contains(TestConstant.USER_READ, TestConstant.USER_WRITE);

        verify(tokenPayload, times(2)).getRoleName();
        verify(tokenPayload, times(2)).getPermissions();
    }

}
