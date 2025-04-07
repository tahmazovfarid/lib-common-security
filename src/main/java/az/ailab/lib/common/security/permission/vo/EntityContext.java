package az.ailab.lib.common.security.permission.vo;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

/**
 * Represents the context of an entity for permission checking.
 * <p>
 * This class encapsulates the various entity attributes (such as user ID, structure path,
 * directorate ID, institution ID, and a flag indicating whether only the structure path
 * should be used for permission checks) that are necessary for determining whether
 * a user has permission to perform an action on the entity.
 * </p>
 * <p>
 * If the {@code useOnlyPath} flag is {@code true}, permission checking will be done solely
 * based on the structure path. If the flag is {@code false}, permission checking will use
 * entity IDs (such as user ID, directorate ID, and institution ID) in addition to or instead of
 * the structure path.
 * </p>
 * <p>
 * This context information is typically used in security and permission-checking logic
 * to evaluate whether a user has the required permissions to act on a specific entity
 * or perform certain actions based on their role and access rights.
 * </p>
 *
 * @param userId        the ID of the user for permission checking
 * @param structurePath the structure path associated with the entity
 * @param directorateId the ID of the directorate related to the entity
 * @param institutionId the ID of the institution associated with the entity
 * @param useOnlyPath   a flag indicating whether only the structure path should be used
 *                      for permission checking. If {@code false}, entity IDs will be used.
 */
public record EntityContext(
        @NotNull
        @Positive
        Long userId,

        @NotBlank
        String structurePath,

        @NotNull
        @Positive
        Long directorateId,

        @NotNull
        @Positive
        Integer institutionId,

        boolean useOnlyPath) {

}
