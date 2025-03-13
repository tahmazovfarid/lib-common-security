package az.ailab.lib.common.security.model;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;

@Getter
@ToString
@EqualsAndHashCode
@AllArgsConstructor
public class UserPrincipal {

    private long id;
    private String fullName;
    private String email;
    private String pin;

    private String rank;
    private String position;

    private UserRole role;
    private List<GrantedAuthority> authorities;
    private UserOrganization organization;

    private TokenPayload payload;

    public static UserPrincipal of(TokenPayload payload, List<GrantedAuthority> authorities) {
        return new UserPrincipal(
                payload.getUserId(),
                payload.getFullName(),
                payload.getEmail(),
                payload.getSubject(),
                payload.getRank(),
                payload.getPosition(),
                buildUserRole(payload),
                authorities,
                buildUserOrganization(payload),
                payload
        );
    }

    private static UserRole buildUserRole(TokenPayload payload) {
        return new UserRole(
                payload.getRoleId(),
                payload.getRoleName(),
                payload.isExecutor(),
                payload.getPermissions()
        );
    }

    private static UserOrganization buildUserOrganization(TokenPayload payload) {
        return new UserOrganization(
                payload.getOrganizationId(),
                payload.getOrganizationName(),
                payload.getOrganizationPrivilege(),
                payload.getDirectOrganizationId(),
                payload.getOrganizationPath(),
                payload.getOrganizationHierarchy()
        );
    }

}
