package az.ailab.lib.common.security.permission;

import az.ailab.lib.common.error.ServiceException;
import az.ailab.lib.common.security.context.UserContextHolder;
import az.ailab.lib.common.security.model.enums.PermissionEnum;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.security.permission.vo.EntityContext;
import java.util.Map;
import java.util.Objects;
import javax.validation.Valid;

/**
 * This class is responsible for checking user permissions based on various levels such as personal, structure,
 * directorate, institution, and system. It verifies whether the current user has the necessary permission
 * based on the provided context (e.g., user ID, institution, directorate, etc.).
 * <p>The permission checking mechanism works by comparing the context of the user (obtained from the current session)
 * with the context of the entity being checked. The permission check is done on different levels depending on
 * the permission type. For example, it can check if the user has access to a specific entity based on their
 * institution, directorate, or personal details.</p>
 * <p>Usage example:</p>
 * <pre>
 * {@code
 * PermissionChecker permissionChecker = new PermissionChecker(entityContext);
 * permissionChecker.check(Permission.ORDER_ASSIGN);  // This will check if the user has ORDER_ASSIGN permission
 * }
 * </pre>
 * <p>In the example above, the `check` method is called with a specific permission (e.g., `Permission.ORDER_ASSIGN`)
 * to verify if the current user has that permission, based on the entity context provided. The class is designed
 * to be used directly for permission checking without the need for extending it.</p>
 */
public class PermissionChecker {

    private final EntityContext entityContext;

    public PermissionChecker(@Valid final EntityContext entityContext) {
        this.entityContext = entityContext;
    }

    /**
     * Checks if the current user has the specified permission.
     * Throws a {@link ServiceException} if the user is not authenticated
     * or does not have the required permission.
     *
     * @param permissionEnum the permission to check for
     * @throws ServiceException if the user is not authenticated or doesn't have the required permission
     */
    public void check(final PermissionEnum permissionEnum) {
        final Map<PermissionEnum, PermissionLevel> permissions = UserContextHolder.getPermissions();
        final PermissionLevel level = permissions.get(permissionEnum);

        if (!UserContextHolder.isAuthenticated() || level == null) {
            throw ServiceException.forbidden();
        }

        final Long currentUserId = UserContextHolder.getUserId();
        final Long currentDirectorateId = UserContextHolder.getDirectorateId();
        final Integer currentInstitutionId = UserContextHolder.getInstitutionId();
        final String currentStructurePath = UserContextHolder.getStructurePath();

        boolean hasPermission = switch (level) {
            case PERSONAL -> Objects.equals(currentUserId, entityContext.userId());
            case STRUCTURE -> currentStructurePath.contains(entityContext.structurePath());
            case DIRECTORATE -> entityContext.useOnlyPath() ?
                    currentStructurePath.contains(resolveDirectoratePath(currentInstitutionId, currentDirectorateId))
                    : Objects.equals(currentDirectorateId, entityContext.directorateId());
            case INSTITUTION -> entityContext.useOnlyPath() ?
                    currentStructurePath.contains(resolveInstitutionPath(currentInstitutionId))
                    : Objects.equals(currentInstitutionId, entityContext.institutionId());
            case SYSTEM -> true;
        };

        if (!hasPermission) {
            throw ServiceException.forbidden();
        }
    }

    /**
     * Builds a path string for institution level filtering.
     * <p>This method creates a path representation for institution-based filtering.
     * It can be overridden by subclasses if the path format changes.</p>
     *
     * @param institutionId the institution ID to create a path for
     * @return a string representation of the institution path
     */
    protected String resolveInstitutionPath(final Integer institutionId) {
        return institutionId.toString();
    }

    /**
     * Builds a path string for directorate level filtering.
     * <p>This method creates a path representation for directorate-based filtering.
     * It can be overridden by subclasses if the path format changes.</p>
     *
     * @param institutionId the institution ID part of the path
     * @param directorateId the directorate ID part of the path
     * @return a string representation of the directorate path
     */
    protected String resolveDirectoratePath(final Integer institutionId, final Long directorateId) {
        return institutionId + "/" + directorateId;
    }

}
