package az.ailab.lib.common.security.context;

import az.ailab.lib.common.security.model.UserPrincipal;
import az.ailab.lib.common.security.model.enums.ActivityType;
import az.ailab.lib.common.security.model.enums.PermissionEnum;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.security.model.enums.RankType;
import az.ailab.lib.common.security.model.enums.RoleType;
import az.ailab.lib.common.security.model.vo.DirectorateInfo;
import az.ailab.lib.common.security.model.vo.InstitutionInfo;
import az.ailab.lib.common.security.model.vo.UserRole;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Provides static access to the currently authenticated user's information.
 */
public final class UserContextHolder {

    private UserContextHolder() {
        // Utility class, no instantiation
    }

    /**
     * Get current authenticated user principal.
     *
     * @return Optional containing the user principal or empty if no authentication
     */
    public static Optional<UserPrincipal> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() instanceof UserPrincipal) {
            return Optional.of((UserPrincipal) authentication.getPrincipal());
        }

        return Optional.empty();
    }

    /**
     * Get current user's ID.
     *
     * @return User ID or null if no authenticated user
     */
    public static Long getUserId() {
        return getCurrentUser().map(UserPrincipal::id).orElse(null);
    }

    /**
     * Get current user's first name.
     *
     * @return first name or null if no authenticated user
     */
    public static String getFirstName() {
        return getCurrentUser().map(UserPrincipal::firstName).orElse(null);
    }

    /**
     * Get current user's last name.
     *
     * @return last name or null if no authenticated user
     */
    public static String getLastName() {
        return getCurrentUser().map(UserPrincipal::lastName).orElse(null);
    }

    /**
     * Get current user's personal identification number.
     *
     * @return PIN or null if no authenticated user
     */
    public static String getPin() {
        return getCurrentUser().map(UserPrincipal::pin).orElse(null);
    }

    /**
     * Get current user's email.
     *
     * @return Email or null if no authenticated user
     */
    public static String getEmail() {
        return getCurrentUser().map(UserPrincipal::email).orElse(null);
    }

    /**
     * Get current user's rank.
     *
     * @return Rank or null if no authenticated user
     */
    public static String getRank() {
        return getCurrentUser().map(UserPrincipal::rank).orElse(null);
    }

    /**
     * Get current user's position.
     *
     * @return Position or null if no authenticated user
     */
    public static String getPosition() {
        return getCurrentUser().map(UserPrincipal::position).orElse(null);
    }

    /**
     * Returns the ID of the structure (department/unit) to which the currently authenticated user directly belongs.
     * <p>
     * This value represents the lowest-level organizational unit associated with the user —
     * not the root institution or higher-level structures.
     * </p>
     *
     * <p><b>Example:</b></p>
     * <pre>
     * Institution: Ministry of Internal Affairs (DİN)
     *   └── Directorate: Criminalistics Department (Kriminalistika idarəsi)
     *       └── Sub-department: Narcotics Division (Narkotiklərlə Mübarizə Şöbəsi)
     *           └── Unit: Personnel Unit for Narcotics (Narkotik üzrə kadrlar şöbəsi) ← User's direct structure
     * </pre>
     *
     * @return the structure ID if user is authenticated, or {@code null} otherwise
     */
    public static Long getDirectStructureId() {
        return getCurrentUser().map(UserPrincipal::directStructureId).orElse(null);
    }

    /* ROLE INFO*/

    /**
     * Retrieves the current authenticated user's role object.
     *
     * @return {@link UserRole} of the current user, or {@code null} if no user is authenticated
     */
    public static UserRole getRole() {
        return getCurrentUser().map(UserPrincipal::role).orElse(null);
    }

    /**
     * Retrieves the ID of the current authenticated user's role.
     *
     * @return role ID, or {@code null} if no user or role is available
     */
    public static Long getRoleId() {
        return Optional.ofNullable(getRole())
                .map(UserRole::id)
                .orElse(null);
    }

    /**
     * Retrieves the name of the current authenticated user's role.
     *
     * @return role name, or {@code null} if no user or role is available
     */
    public static String getRoleName() {
        return Optional.ofNullable(getRole())
                .map(UserRole::name)
                .orElse(null);
    }

    /**
     * Retrieves the type of the current authenticated user's role.
     *
     * @return {@link RoleType}, or {@code null} if no user or role type is available
     */
    public static RoleType getRoleType() {
        return Optional.ofNullable(getRole())
                .map(UserRole::type)
                .orElse(null);
    }

    /**
     * Checks whether the current user has the {@link RoleType#EXPERT} role.
     *
     * @return {@code true} if the user is an Expert; {@code false} otherwise
     */
    public static boolean isExpert() {
        return RoleType.EXPERT.equals(getRoleType());
    }

    /**
     * Checks whether the current user has the {@link RoleType#INSTITUTION_ADMIN} role.
     *
     * @return {@code true} if the user is an Institution Admin; {@code false} otherwise
     */
    public static boolean isInstitutionAdmin() {
        return RoleType.INSTITUTION_ADMIN.equals(getRoleType());
    }

    /**
     * Checks whether the current user has the {@link RoleType#DIRECTORATE_ADMIN} role.
     *
     * @return {@code true} if the user is a Directorate Admin; {@code false} otherwise
     */
    public static boolean isDirectorateAdmin() {
        return RoleType.DIRECTORATE_ADMIN.equals(getRoleType());
    }

    /**
     * Retrieves the permission map assigned to the currently authenticated user's role.
     *
     * @return a {@link Map} of {@link PermissionEnum} to {@link PermissionLevel}, or an empty map if the user is not authenticated.
     */
    public static Map<PermissionEnum, PermissionLevel> getPermissions() {
        return Optional.ofNullable(getRole())
                .map(UserRole::permissions)
                .orElse(Collections.emptyMap());
    }

    /* INSTITUTION INFO */

    /**
     * Retrieves the current authenticated user's institution information.
     *
     * @return the {@link InstitutionInfo} of the authenticated user, or {@code null} if not authenticated
     */
    public static InstitutionInfo getInstitution() {
        return getCurrentUser().map(UserPrincipal::institution).orElse(null);
    }

    /**
     * Retrieves the ID of the current authenticated user's institution.
     *
     * @return the institution ID, or {@code null} if the user is not authenticated or institution is unavailable
     */
    public static Integer getInstitutionId() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::id)
                .orElse(null);
    }

    /**
     * Retrieves the name of the current authenticated user's institution.
     *
     * @return the institution name, or {@code null} if the user is not authenticated or institution is unavailable
     */
    public static String getInstitutionName() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::name)
                .orElse(null);
    }

    /**
     * Retrieves the activity type of the current authenticated user's institution.
     *
     * @return the {@link ActivityType} of the current authenticated user's institution, or {@code null} if not authenticated
     */
    public static ActivityType getActivityType() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::getActivityType)
                .orElse(null);
    }

    /**
     * Retrieves the rank type of the current authenticated user's institution.
     *
     * @return the Rank type of the current authenticated user's institution, or {@code null} if not authenticated
     */
    public static RankType getInstitutionRankType() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::getRankType)
                .orElse(null);
    }

    /**
     * Checks whether the current user's institution acts as a provider.
     * <p>
     * A provider institution supplies services or resources within the system.
     * The check returns {@code true} if the institution's activity type is either {@code PROVIDER} or {@code BOTH}.
     * </p>
     *
     * @return {@code true} if the institution is a provider or both; {@code false} otherwise
     */
    public static boolean isInstitutionProvider() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::getActivityType)
                .map(type -> type == ActivityType.PROVIDER || type == ActivityType.BOTH)
                .orElse(false);
    }

    /**
     * Checks whether the current user's institution acts as a requester.
     * <p>
     * A requester institution consumes services or resources within the system.
     * The check returns {@code true} only if the activity type is {@code REQUESTER}.
     * </p>
     *
     * @return {@code true} if the institution is a requester; {@code false} otherwise
     */
    public static boolean isInstitutionRequester() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::getActivityType)
                .map(ActivityType.REQUESTER::equals)
                .orElse(false);
    }

    /**
     * Checks whether the current user's institution is marked as both provider and requester.
     * <p>
     * This is useful when the institution can both offer and consume services/resources.
     * </p>
     *
     * @return {@code true} if the activity type is {@code BOTH}; {@code false} otherwise
     */
    public static boolean areInstitutionProviderAndRequester() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::getActivityType)
                .map(ActivityType.BOTH::equals)
                .orElse(false);
    }

    /**
     * Retrieves the path of the current authenticated user's institution.
     *
     * @return the institution path as a string, or {@code null} if unavailable
     */
    public static String getStructurePath() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::path)
                .orElse(null);
    }

    /**
     * Retrieves the directorate information of the current authenticated user's institution.
     *
     * @return the {@link DirectorateInfo} object, or {@code null} if unavailable
     */
    public static DirectorateInfo getDirectorateInfo() {
        return Optional.ofNullable(getInstitution())
                .map(InstitutionInfo::directorateInfo)
                .orElse(null);
    }

    /**
     * Retrieves the ID of the directorate associated with the current user's institution.
     *
     * @return the directorate ID, or {@code null} if unavailable
     */
    public static Long getDirectorateId() {
        return Optional.ofNullable(getDirectorateInfo())
                .map(DirectorateInfo::id)
                .orElse(null);
    }

    /**
     * Retrieves the name of the directorate associated with the current user's institution.
     *
     * @return the directorate name, or {@code null} if unavailable
     */
    public static String getDirectorateName() {
        return Optional.ofNullable(getDirectorateInfo())
                .map(DirectorateInfo::name)
                .orElse(null);
    }

    /**
     * Retrieves the activity type of the directorate associated with the current user's institution.
     *
     * @return the directorate activity type, or {@code null} if unavailable
     */
    public static String getDirectorateActivityType() {
        return Optional.ofNullable(getDirectorateInfo())
                .map(DirectorateInfo::activityType)
                .orElse(null);
    }

    /**
     * Checks whether the directorate associated with the current user's institution acts as a provider.
     * <p>
     * A provider directorate supplies services or resources in the system.
     * This check passes if the directorate's activity type is {@code PROVIDER}.
     * </p>
     *
     * @return {@code true} if the directorate is a provider, {@code false} otherwise
     */
    public static boolean isDirectorateProvider() {
        return Optional.ofNullable(getDirectorateInfo())
                .map(DirectorateInfo::activityType)
                .map(type -> ActivityType.PROVIDER.name().equals(type))
                .orElse(false);
    }

    /**
     * Checks whether the directorate associated with the current user's institution acts as a requester.
     * <p>
     * A requester directorate consumes services or resources provided by others in the system.
     * This check passes only if the directorate's activity type is {@code REQUESTER}.
     * </p>
     *
     * @return {@code true} if the directorate is a requester, {@code false} otherwise
     */
    public static boolean isDirectorateRequester() {
        return Optional.ofNullable(getDirectorateInfo())
                .map(DirectorateInfo::activityType)
                .map(ActivityType.REQUESTER.name()::equals)
                .orElse(false);
    }

    /**
     * Check if a user is authenticated.
     *
     * @return true if authenticated, false otherwise
     */
    public static boolean isAuthenticated() {
        return getCurrentUser().isPresent();
    }

}
