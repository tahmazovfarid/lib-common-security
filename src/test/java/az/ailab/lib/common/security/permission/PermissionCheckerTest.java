package az.ailab.lib.common.security.permission;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import az.ailab.lib.common.error.ServiceException;
import az.ailab.lib.common.security.context.UserContextHolder;
import az.ailab.lib.common.security.model.enums.Permission;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.security.permission.vo.EntityContext;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PermissionCheckerTest {

    @Mock
    private EntityContext entityContext;

    private PermissionChecker permissionChecker;

    @BeforeEach
    void setUp() {
        permissionChecker = new PermissionChecker(entityContext);
    }

    @Test
    void testSystemLevelPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.SYSTEM);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);

            // Execute and verify no exception is thrown for system level
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testInstitutionLevelPermissionWithIdBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.INSTITUTION);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);

            // Setup entity context
            when(entityContext.useOnlyPath()).thenReturn(false);
            when(entityContext.institutionId()).thenReturn(123);

            // Execute and verify success when institution IDs match
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));

            // Verify failure when institution IDs don't match
            when(entityContext.institutionId()).thenReturn(456);
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testInstitutionLevelPermissionWithPathBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.INSTITUTION);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("/123/456/");

            // Setup entity context
            when(entityContext.useOnlyPath()).thenReturn(true);
            when(entityContext.structurePath()).thenReturn("123");

            // Execute and verify success when path contains institution path
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));

            // Verify failure when path doesn't contain institution path
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("/999/888/");
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testDirectorateLevelPermissionWithIdBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.DIRECTORATE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getDirectorateId).thenReturn(456L);

            // Setup entity context
            when(entityContext.useOnlyPath()).thenReturn(false);
            when(entityContext.directorateId()).thenReturn(456L);

            // Execute and verify success when directorate IDs match
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));

            // Verify failure when directorate IDs don't match
            when(entityContext.directorateId()).thenReturn(789L);
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testDirectorateLevelPermissionWithPathBasedFiltering() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.DIRECTORATE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);
            mockedStatic.when(UserContextHolder::getDirectorateId).thenReturn(456L);
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("/123/456/789/");

            // Setup entity context
            when(entityContext.useOnlyPath()).thenReturn(true);
            when(entityContext.structurePath()).thenReturn("123/456");

            // Execute and verify success when path contains directorate path
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));

            // Verify failure when path doesn't contain directorate path
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("/123/999/");
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testStructureLevelPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.STRUCTURE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("/1/2/3/");

            // Setup entity context
            when(entityContext.structurePath()).thenReturn("1/2/3");

            // Execute and verify success when path is contained
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));

            // Verify failure when path is not contained
            when(entityContext.structurePath()).thenReturn("4/5/6");
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testPersonalLevelPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.PERSONAL);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getUserId).thenReturn(789L);

            // Setup entity context
            when(entityContext.userId()).thenReturn(789L);

            // Execute and verify success when user IDs match
            assertDoesNotThrow(() -> permissionChecker.check(Permission.ORDER_READ));

            // Verify failure when user IDs don't match
            when(entityContext.userId()).thenReturn(999L);
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testUnauthenticatedUser() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks for unauthenticated user
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(false);

            // Execute and verify exception is thrown
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testMissingPermission() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks with missing permission
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(new HashMap<>());

            // Execute and verify exception is thrown
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testNullPermissionLevel() {
        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup UserContextHolder mocks with null permission level
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, null);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);

            // Execute and verify exception is thrown
            assertThrows(ServiceException.class, () -> permissionChecker.check(Permission.ORDER_READ));
        }
    }

    @Test
    void testCustomPermissionChecker() {
        // Custom implementation for testing protected methods
        class TestPermissionChecker extends PermissionChecker {
            public TestPermissionChecker(EntityContext entityContext) {
                super(entityContext);
            }

            @Override
            protected String resolveInstitutionPath(Integer institutionId) {
                return "INST-" + institutionId;
            }

            @Override
            protected String resolveDirectoratePath(Integer institutionId, Long directorateId) {
                return "INST-" + institutionId + "-DIR-" + directorateId;
            }
        }

        TestPermissionChecker customChecker = new TestPermissionChecker(entityContext);

        try (MockedStatic<UserContextHolder> mockedStatic = mockStatic(UserContextHolder.class)) {
            // Setup for directorate level test with custom path format
            mockedStatic.when(UserContextHolder::isAuthenticated).thenReturn(true);

            Map<Permission, PermissionLevel> permissions = new HashMap<>();
            permissions.put(Permission.ORDER_READ, PermissionLevel.DIRECTORATE);
            mockedStatic.when(UserContextHolder::getPermissions).thenReturn(permissions);
            mockedStatic.when(UserContextHolder::getInstitutionId).thenReturn(123);
            mockedStatic.when(UserContextHolder::getDirectorateId).thenReturn(456L);

            // Custom path format
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("INST-123-DIR-456");

            when(entityContext.useOnlyPath()).thenReturn(true);

            // Should pass with custom format path
            assertDoesNotThrow(() -> customChecker.check(Permission.ORDER_READ));

            // Should fail with incorrect path
            mockedStatic.when(UserContextHolder::getStructurePath).thenReturn("/123/456/");
            assertThrows(ServiceException.class, () -> customChecker.check(Permission.ORDER_READ));
        }
    }

}