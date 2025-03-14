package az.ailab.lib.common.security.context;

import az.ailab.lib.common.security.model.UserOrganization;
import az.ailab.lib.common.security.model.UserPrincipal;
import az.ailab.lib.common.security.model.UserRole;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
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
        return getCurrentUser().map(UserPrincipal::getId).orElse(null);
    }

    /**
     * Get current user's full name.
     *
     * @return Full name or null if no authenticated user
     */
    public static String getFullName() {
        return getCurrentUser().map(UserPrincipal::getFullName).orElse(null);
    }

    /**
     * Get current user's personal identification number.
     *
     * @return PIN or null if no authenticated user
     */
    public static String getPin() {
        return getCurrentUser().map(UserPrincipal::getPin).orElse(null);
    }

    /**
     * Get current user's email.
     *
     * @return Email or null if no authenticated user
     */
    public static String getEmail() {
        return getCurrentUser().map(UserPrincipal::getEmail).orElse(null);
    }

    /**
     * Get current user's rank.
     *
     * @return Rank or null if no authenticated user
     */
    public static String getRank() {
        return getCurrentUser().map(UserPrincipal::getRank).orElse(null);
    }

    /**
     * Get current user's position.
     *
     * @return Position or null if no authenticated user
     */
    public static String getPosition() {
        return getCurrentUser().map(UserPrincipal::getPosition).orElse(null);
    }

    /**
     * Get current user's role information.
     *
     * @return UserRole or null if no authenticated user
     */
    public static UserRole getRole() {
        return getCurrentUser().map(UserPrincipal::getRole).orElse(null);
    }

    /**
     * Get current user's role ID.
     *
     * @return Role ID or null if no authenticated user
     */
    public static Long getRoleId() {
        UserRole role = getRole();
        return role != null ? role.id() : null;
    }

    /**
     * Check if the current user is an executor.
     *
     * @return true if the user is an executor, false otherwise
     */
    public static boolean isExecutor() {
        UserRole role = getRole();
        return role != null && role.isExecutor();
    }

    /**
     * Get current user's permissions.
     *
     * @return Set of permissions or empty set if no authenticated user
     */
    public static Set<String> getPermissions() {
        UserRole role = getRole();
        return role != null ? role.permissions() : Collections.emptySet();
    }

    /**
     * Check if a user is authenticated.
     *
     * @return true if authenticated, false otherwise
     */
    public static boolean isOrgProvider() {
        return getCurrentUser().map(UserPrincipal::isOrgProvider).orElse(false);
    }

    /**
     * Get current user's organization information.
     *
     * @return UserOrganization or null if no authenticated user
     */
    public static UserOrganization getOrganization() {
        return getCurrentUser().map(UserPrincipal::getOrganization).orElse(null);
    }

    /**
     * Get current user's organization ID.
     *
     * @return Organization ID or null if no authenticated user
     */
    public static Long getOrganizationId() {
        UserOrganization org = getOrganization();
        return org != null ? org.id() : null;
    }

    /**
     * Get current user's direct organization ID.
     *
     * @return Direct organization ID or null if no authenticated user
     */
    public static Long getDirectOrganizationId() {
        UserOrganization org = getOrganization();
        return org != null ? org.directOrganizationId() : null;
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
