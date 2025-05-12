package az.ailab.lib.common.security.permission;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import az.ailab.lib.common.security.context.UserContextHolder;
import az.ailab.lib.common.security.model.enums.PermissionEnum;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.util.specification.FilterOperations;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.jpa.domain.Specification;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PermissionAwareFilterSpecificationTest {

    @Mock
    private Root<TestEntity> root;

    @Mock
    private CriteriaQuery<?> query;

    @Mock
    private CriteriaBuilder cb;

    @Mock
    private Path<Long> userIdPath;

    @Mock
    private Path<Long> directorateIdPath;

    @Mock
    private Path<Integer> institutionIdPath;

    @Mock
    private Path<String> structurePathPath;

    @Mock
    private Predicate predicate;

    private TestFilterSpecification specification;

    @BeforeEach
    void setUp() {
        specification = new TestFilterSpecification();

        when(root.<Long>get("userId")).thenReturn(userIdPath);
        when(root.<Long>get("directorateId")).thenReturn(directorateIdPath);
        when(root.<Integer>get("institutionId")).thenReturn(institutionIdPath);
        when(root.<String>get("structurePath")).thenReturn(structurePathPath);
    }

    @Test
    void testSystemLevelPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.SYSTEM);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);

            // FilterOperations mock
            Specification<TestEntity> alwaysTrueSpec = (r, q, c) -> predicate;
            filterOpsMock.when(FilterOperations::alwaysTrue)
                    .thenReturn(alwaysTrueSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
        }
    }

    @Test
    void testInstitutionLevelPermissionWithIdBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.INSTITUTION);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);

            // Configure specification to use ID-based filtering
            specification.setUseOnlyPath(false);

            // FilterOperations mock
            Specification<TestEntity> equalsSpec = (r, q, c) -> predicate;
            filterOpsMock.when(() -> FilterOperations.equals(eq(123), any()))
                    .thenReturn(equalsSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
        }
    }

    @Test
    void testInstitutionLevelPermissionWithPathBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.INSTITUTION);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);

            specification.setUseOnlyPath(true);

            Specification<TestEntity> startsWithSpec = (r, q, c) -> predicate;
            filterOpsMock.when(() -> FilterOperations.startsWith(anyString(), any()))
                    .thenReturn(startsWithSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
            filterOpsMock.verify(() -> FilterOperations.startsWith(eq("123"), any()));
        }
    }

    @Test
    void testDirectorateLevelPermissionWithIdBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.DIRECTORATE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getDirectorateId).thenReturn(456L);

            // Configure specification to use ID-based filtering
            specification.setUseOnlyPath(false);

            // FilterOperations mock
            Specification<TestEntity> equalsSpec = (r, q, c) -> predicate;
            filterOpsMock.when(() -> FilterOperations.equals(eq(456L), any()))
                    .thenReturn(equalsSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
        }
    }

    @Test
    void testDirectorateLevelPermissionWithPathBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.DIRECTORATE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);
            mockedStatic.when(UserContextHolder::getDirectorateId).thenReturn(456L);

            // Configure specification to use path-based filtering
            specification.setUseOnlyPath(true);

            Specification<TestEntity> startsWithSpec = (r, q, c) -> predicate;
            filterOpsMock.when(() -> FilterOperations.startsWith(anyString(), any()))
                    .thenReturn(startsWithSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
            filterOpsMock.verify(() -> FilterOperations.startsWith(eq("123/456"), any()));
        }
    }

    @Test
    void testStructureLevelPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.STRUCTURE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("1/2/3");

            // FilterOperations mock
            Specification<TestEntity> startsWithSpec = (r, q, c) -> predicate;
            filterOpsMock.when(() -> FilterOperations.startsWith(anyString(), any()))
                    .thenReturn(startsWithSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
            filterOpsMock.verify(() -> FilterOperations.startsWith(eq("1/2/3"), any()));
        }
    }

    @Test
    void testPersonalLevelPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.PERSONAL);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getUserId).thenReturn(789L);

            // FilterOperations mock
            Specification<TestEntity> equalsSpec = (r, q, c) -> predicate;
            filterOpsMock.when(() -> FilterOperations.equals(eq(789L), any()))
                    .thenReturn(equalsSpec);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(predicate, actualPredicate);
        }
    }

    @Test
    void testCombinedSpecifications() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class);
                MockedStatic<FilterOperations> filterOpsMock = mockStatic(FilterOperations.class)) {

            // UserContextHolder mock
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<PermissionEnum, PermissionLevel> permissions = new HashMap<>();
            permissions.put(PermissionEnum.ORDER_READ, PermissionLevel.PERSONAL);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getUserId).thenReturn(789L);

            // Configure basic specification to return a predicate
            specification.setBasicPredicateEnabled(true);

            // FilterOperations mock
            Predicate userPredicate = mock(Predicate.class);
            Specification<TestEntity> equalsSpec = (r, q, c) -> userPredicate;
            filterOpsMock.when(() -> FilterOperations.equals(eq(789L), any()))
                    .thenReturn(equalsSpec);

            // Mock basic predicate
            Predicate basicPredicate = mock(Predicate.class);
            when(cb.equal(institutionIdPath, 999)).thenReturn(basicPredicate);

            // Mock AND predicate
            Predicate combinedPredicate = mock(Predicate.class);
            when(cb.and(basicPredicate, userPredicate)).thenReturn(combinedPredicate);

            // Execute
            Specification<TestEntity> result = specification.toSpecificationWithPermission(PermissionEnum.ORDER_READ);
            Predicate actualPredicate = result.toPredicate(root, query, cb);

            // Verify
            assertEquals(combinedPredicate, actualPredicate);
            verify(cb).and(basicPredicate, userPredicate);
        }
    }

    // Test entity and specification implementation for testing purposes
    private static class TestEntity {

        private Long userId;
        private Long directorateId;
        private Integer institutionId;
        private String structurePath;

    }

    private static class TestFilterSpecification extends PermissionAwareFilterSpecification<TestEntity> {
        private boolean useOnlyPathFlag = false;
        private boolean basicPredicateEnabled = false;

        public void setUseOnlyPath(boolean useOnlyPath) {
            this.useOnlyPathFlag = useOnlyPath;
        }

        public void setBasicPredicateEnabled(boolean enabled) {
            this.basicPredicateEnabled = enabled;
        }

        @Override
        public Specification<TestEntity> toSpecification() {
            if (!basicPredicateEnabled) {
                return null;
            }

            // Return a simple specification for testing combined specifications
            return (root, query, cb) -> cb.equal(root.get("institutionId"), 999);
        }

        @Override
        public Function<Root<TestEntity>, Expression<Long>> getUserId() {
            return root -> root.get("userId");
        }

        @Override
        public Function<Root<TestEntity>, Expression<Long>> getDirectorateId() {
            return root -> root.get("directorateId");
        }

        @Override
        public Function<Root<TestEntity>, Expression<Integer>> getInstitutionId() {
            return root -> root.get("institutionId");
        }

        @Override
        public Function<Root<TestEntity>, Expression<String>> getStructurePath() {
            return root -> root.get("structurePath");
        }

        @Override
        public boolean useOnlyPath() {
            return useOnlyPathFlag;
        }
    }

}