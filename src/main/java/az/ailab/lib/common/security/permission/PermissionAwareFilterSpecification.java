package az.ailab.lib.common.security.permission;

import static az.ailab.lib.common.util.specification.FilterOperations.alwaysTrue;
import static az.ailab.lib.common.util.specification.FilterOperations.startsWith;

import az.ailab.lib.common.error.ServiceException;
import az.ailab.lib.common.security.context.UserContextHolder;
import az.ailab.lib.common.security.model.enums.Permission;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.util.specification.FilterOperations;
import az.ailab.lib.common.util.specification.FilterSpecification;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Root;
import java.util.Map;
import java.util.function.Function;
import org.springframework.data.jpa.domain.Specification;

/**
 * Abstract class that adds permission-based filtering capabilities to filter specifications.
 * <p>This class extends the base {@link FilterSpecification} interface to apply permission-based
 * access control on database queries. It filters data based on the user's permission level
 * (SYSTEM, INSTITUTION, DIRECTORATE, STRUCTURE, or PERSONAL) by automatically adding
 * the necessary predicates to the query.</p>
 * Usage example:
 * <pre>{@code
 * public class OrderFilterSpecification extends PermissionAwareFilterSpecification<Order> {
 *     private final OrderFilter filter;
 *
 *     public OrderFilterSpecification(OrderFilter filter) {
 *         this.filter = filter;
 *     }
 *
 *     @Override
 *     public Specification<Order> toSpecification() {
 *         return Specification.where(
 *                 FilterOperations.equals(filter.getOrderNumber(), root -> root.get("orderNumber"))
 *                 .and(FilterOperations.equals(filter.getStatus(), root -> root.get("status")))
 *                 .and(FilterOperations.dateBetween(filter.getStartDate(), filter.getEndDate(), root -> root.get("createdAt")))
 *                 .and(FilterOperations.in(filter.getTypes(), root -> root.get("type")))
 *         );
 *     }
 *
 *     @Override
 *     public Function<Root<Order>, Expression<Long>> getUserId() {
 *         return root -> root.get("createdBy");
 *     }
 *
 *     @Override
 *     public Function<Root<Order>, Expression<Long>> getDirectorateId() {
 *         return root -> root.get("directorateId");
 *     }
 *
 *     @Override
 *     public Function<Root<Order>, Expression<Integer>> getInstitutionId() {
 *         return root -> root.get("institutionId");
 *     }
 *
 *     @Override
 *     public Function<Root<Order>, Expression<String>> getStructurePath() {
 *         return root -> root.get("structurePath");
 *     }
 *
 *     @Override
 *     public boolean useOnlyPath() {
 *         return true;
 *     }
 * }
 *
 * // In service:
 * @Service
 * public class OrderService {
 *     private final OrderRepository orderRepository;
 *
 *     @Autowired
 *     public OrderService(OrderRepository orderRepository) {
 *         this.orderRepository = orderRepository;
 *     }
 *
 *     @PreAuthorize("hasAuthority('ORDER_READ')")
 *     public Page<Order> findOrders(Pageable pageable, OrderFilter filter) {
 *         // Apply both regular filters and permission-based filters
 *         OrderFilterSpecification spec = new OrderFilterSpecification(filter)
 *              .toSpecificationAndApplyPermission(Permission.ORDER_READ);
 *
 *         return orderRepository.findAll(finalSpec, pageable);
 *     }
 * }
 * }</pre>
 * <p>Implementing classes need to define how entity fields map to permission-related attributes
 * by implementing the abstract methods.</p>
 *
 * @param <T> the entity type this specification will be applied to
 * @see FilterSpecification
 * @see Permission
 * @see PermissionLevel
 */
public abstract class PermissionAwareFilterSpecification<T> implements FilterSpecification<T> {

    /**
     * Combines the base filter specification with permission-based filtering.
     * <p>This method first gets the base specification from {@link #toSpecification()},
     * then creates a permission-based specification using {@link #createPermissionSpecification(Permission)},
     * and finally combines them with logical AND.</p>
     *
     * @param permission the permission to check against the user's granted permissions
     * @return a combined specification with both filter and permission constraints
     */
    public Specification<T> toSpecificationWithPermission(final Permission permission) {
        Specification<T> specification = toSpecification();
        Specification<T> permissionSpec = createPermissionSpecification(permission);

        return specification != null ? specification.and(permissionSpec) : permissionSpec;
    }

    /**
     * Creates a specification that filters entities based on user's permission level.
     * <p>This method retrieves the user's permission level for the specified permission
     * and creates appropriate predicates based on that level. For example, with PERSONAL level,
     * it filters only entities created by the current user.</p>
     *
     * @param permission the permission to check against the user's granted permissions
     * @return a specification that restricts access based on permission level
     */
    private Specification<T> createPermissionSpecification(final Permission permission) {
        if (!UserContextHolder.isAuthenticated()) {
            throw ServiceException.forbidden();
        }
        final Map<Permission, PermissionLevel> permissions = UserContextHolder.getPermissions();
        final PermissionLevel level = permissions.get(permission);

        if (level == null) {
            throw ServiceException.forbidden();
        }

        final Long currentUserId = UserContextHolder.getUserId();
        final Long currentDirectorateId = UserContextHolder.getDirectorateId();
        final Integer currentInstitutionId = UserContextHolder.getInstitutionId();
        final String currentStructurePath = UserContextHolder.getStructurePath();

        return switch (level) {
            case SYSTEM -> alwaysTrue(); // Full access
            case INSTITUTION -> useOnlyPath() ? startsWith(resolveInstitutionPath(currentInstitutionId), getStructurePath())
                    : FilterOperations.equals(currentInstitutionId, getInstitutionId());

            case DIRECTORATE ->
                    useOnlyPath() ? startsWith(resolveDirectoratePath(currentInstitutionId, currentDirectorateId), getStructurePath())
                            : FilterOperations.equals(currentDirectorateId, getDirectorateId());

            case STRUCTURE -> startsWith(currentStructurePath, getStructurePath());
            case PERSONAL -> FilterOperations.equals(currentUserId, getUserId());
        };
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

    /**
     * Provides a function to extract the user ID from the entity.
     * <p>This method should return a function that, when applied to a root,
     * returns the expression representing the user ID field of the entity.
     * Used for PERSONAL level permission filtering.</p>
     *
     * @return a function that extracts the user ID expression from the root
     */
    public abstract Function<Root<T>, Expression<Long>> getUserId();

    /**
     * Provides a function to extract the directorate ID from the entity.
     * <p>This method should return a function that, when applied to a root,
     * returns the expression representing the directorate ID field of the entity.
     * Used for DIRECTORATE level permission filtering.</p>
     *
     * @return a function that extracts the directorate ID expression from the root
     */
    public abstract Function<Root<T>, Expression<Long>> getDirectorateId();

    /**
     * Provides a function to extract the institution ID from the entity.
     * <p>This method should return a function that, when applied to a root,
     * returns the expression representing the institution ID field of the entity.
     * Used for INSTITUTION level permission filtering.</p>
     *
     * @return a function that extracts the institution ID expression from the root
     */
    public abstract Function<Root<T>, Expression<Integer>> getInstitutionId();

    /**
     * Provides a function to extract the structure path from the entity.
     * <p>This method should return a function that, when applied to a root,
     * returns the expression representing the structure path field of the entity.
     * Used for STRUCTURE level permission filtering and path-based filtering.</p>
     *
     * @return a function that extracts the structure path expression from the root
     */
    public abstract Function<Root<T>, Expression<String>> getStructurePath();

    /**
     * Determines whether to use path-based filtering instead of ID-based filtering.
     * <p>When this method returns true, the specification will use structure paths
     * for filtering at institution and directorate levels. When false, it will
     * use direct ID comparisons.</p>
     * <p>This should be overridden by subclasses to customize the filtering approach.</p>
     *
     * @return true to use path-based filtering, false to use ID-based filtering
     */
    public abstract boolean useOnlyPath();

}
