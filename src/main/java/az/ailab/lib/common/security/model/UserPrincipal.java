package az.ailab.lib.common.security.model;

import az.ailab.lib.common.security.model.enums.Permission;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.security.model.enums.RoleType;
import az.ailab.lib.common.security.model.vo.DirectorateInfo;
import az.ailab.lib.common.security.model.vo.InstitutionInfo;
import az.ailab.lib.common.security.model.vo.UserRole;
import az.ailab.lib.common.util.EnumUtil;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;

public record UserPrincipal(
        Long id,
        String firstName,
        String lastName,
        String email,
        String pin,
        String rank,
        String position,
        Long directStructureId,
        UserRole role,
        List<GrantedAuthority> authorities,
        InstitutionInfo institution,
        TokenPayload payload) {

    public static UserPrincipal of(final TokenPayload payload, final List<GrantedAuthority> authorities) {
        return new UserPrincipal(
                payload.getUserId(),
                payload.getFirstName(),
                payload.getLastName(),
                payload.getEmail(),
                payload.getSubject(),
                payload.getRank(),
                payload.getPosition(),
                payload.getDirectStructureId(),
                resolveUserRole(payload),
                authorities,
                resolveUserInstitution(payload),
                payload
        );
    }

    private static UserRole resolveUserRole(final TokenPayload payload) {
        final RoleType roleType = resolveRoleType(payload.getRoleType());
        final Map<Permission, PermissionLevel> permissionsMap = resolvePermissions(payload.getPermissions());

        return new UserRole(
                payload.getRoleId(),
                payload.getRoleName(),
                roleType,
                permissionsMap
        );
    }

    private static Map<Permission, PermissionLevel> resolvePermissions(final Map<String, String> permissions) {
        final Map<Permission, PermissionLevel> permissionsMap = new EnumMap<>(Permission.class);

        permissions.forEach((key, value) -> {
            final Permission permission = EnumUtil.getOptEnumConstant(Permission.class, key)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid permission: " + key));

            final PermissionLevel permissionLevel = EnumUtil.getOptEnumConstant(PermissionLevel.class, value)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid permission level: " + value));

            permissionsMap.put(permission, permissionLevel);
        });

        return permissionsMap;
    }

    private static RoleType resolveRoleType(final String roleType) {
        return EnumUtil.getOptEnumConstant(RoleType.class, roleType)
                .orElseThrow(() -> new IllegalArgumentException("Invalid role type: " + roleType));

    }

    private static InstitutionInfo resolveUserInstitution(final TokenPayload payload) {
        return new InstitutionInfo(
                payload.getInstitutionId(),
                payload.getInstitutionName(),
                payload.getInstitutionActivityType(),
                payload.getStructurePath(),
                resolveDirectorate(payload)
        );
    }

    private static DirectorateInfo resolveDirectorate(final TokenPayload payload) {
        return new DirectorateInfo(
                payload.getDirectorateId(),
                payload.getDirectorateName(),
                payload.getDirectorateActivityType()
        );
    }

}
