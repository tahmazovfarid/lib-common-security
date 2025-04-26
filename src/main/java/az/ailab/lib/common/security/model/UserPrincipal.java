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

/**
 * Represents an authenticated user principal within Spring Security context.
 * <p>
 * Encapsulates user identity (ID, name, email, PIN), role and permission details,
 * institution and directorate metadata, and the original token payload.
 * Also holds granted authorities for Spring Security authorization checks.
 * </p>
 *
 * <p>Use {@link #of(TokenPayload, List)} factory to create this object from a parsed JWT payload.</p>
 *
 * @param id                the user's unique identifier
 * @param firstName         the user's first name
 * @param lastName          the user's last name
 * @param email             the user's email address
 * @param pin               the subject claim from JWT (e.g. PIN or username)
 * @param rank              the user's rank
 * @param position          the user's position within the organization
 * @param directStructureId the ID of the direct structure (institutional unit)
 * @param role              a {@link UserRole} combining role type and permissions
 * @param authorities       the list of {@link GrantedAuthority} for Spring Security
 * @param institution       the {@link InstitutionInfo} associated with the user
 * @param payload           the original {@link TokenPayload} for further inspection
 *
 * @author tahmazovfarid
 * @since 1.0
 */
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
        TokenPayload payload
) {

    /**
     * Factory method to build a UserPrincipal from a TokenPayload and authorities.
     * <p>
     * Converts raw token data (role type string, permission map) into typed enums and
     * wraps them in {@link UserRole} and {@link InstitutionInfo}/{@link DirectorateInfo} VOs.
     * </p>
     *
     * @param payload     the parsed JWT payload containing all user and context claims
     * @param authorities the granted authorities derived from role and permission claims
     * @return a fully populated {@link UserPrincipal} instance
     * @throws IllegalArgumentException if any enum conversion fails due to invalid values
     */
    public static UserPrincipal of(final TokenPayload payload, final List<GrantedAuthority> authorities) {
        return new UserPrincipal(
                payload.getUserId(),
                payload.getFirstName(),
                payload.getLastName(),
                payload.getEmail(),
                payload.getSubject(),
                payload.getRank(),
                payload.getPosition(),
                payload.getStructureId(),
                resolveUserRole(payload),
                authorities,
                resolveUserInstitution(payload),
                payload
        );
    }

    /**
     * Resolves the user's role type and maps permissions to their levels.
     *
     * @param payload the token payload containing raw role and permissions data
     * @return a {@link UserRole} value object
     */
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

    /**
     * Converts string-based permission map into enum-based map.
     *
     * @param permissions raw map of permission name → level name
     * @return an {@link EnumMap} of {@link Permission} → {@link PermissionLevel}
     * @throws IllegalArgumentException if any permission or level string is invalid
     */
    private static Map<Permission, PermissionLevel> resolvePermissions(final Map<String, String> permissions) {
        final Map<Permission, PermissionLevel> permissionsMap = new EnumMap<>(Permission.class);
        permissions.forEach((key, value) -> {
            final Permission permission = EnumUtil.getOptEnumConstant(Permission.class, key)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid permission: " + key));
            final PermissionLevel level = EnumUtil.getOptEnumConstant(PermissionLevel.class, value)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid permission level: " + value));
            permissionsMap.put(permission, level);
        });
        return permissionsMap;
    }

    /**
     * Converts the raw roleType string into a {@link RoleType} enum.
     *
     * @param roleType the raw role type value
     * @return the corresponding {@link RoleType} enum
     * @throws IllegalArgumentException if the role type is invalid
     */
    private static RoleType resolveRoleType(final String roleType) {
        return EnumUtil.getOptEnumConstant(RoleType.class, roleType)
                .orElseThrow(() -> new IllegalArgumentException("Invalid role type: " + roleType));
    }

    /**
     * Builds the {@link InstitutionInfo} value object from payload data.
     *
     * @param payload the token payload
     * @return an {@link InstitutionInfo} with nested {@link DirectorateInfo}
     */
    private static InstitutionInfo resolveUserInstitution(final TokenPayload payload) {
        return new InstitutionInfo(
                payload.getInstitutionId(),
                payload.getInstitutionName(),
                payload.getInstitutionActivityType(),
                payload.getInstitutionRankType(),
                payload.getStructurePath(),
                resolveDirectorate(payload)
        );
    }

    /**
     * Constructs {@link DirectorateInfo} if directorate data is present.
     *
     * @param payload the token payload
     * @return a {@link DirectorateInfo} or with null fields if absent
     */
    private static DirectorateInfo resolveDirectorate(final TokenPayload payload) {
        return new DirectorateInfo(
                payload.getDirectorateId(),
                payload.getDirectorateName(),
                payload.getDirectorateActivityType()
        );
    }

}