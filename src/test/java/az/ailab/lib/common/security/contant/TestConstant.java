package az.ailab.lib.common.security.contant;

import az.ailab.lib.common.security.model.enums.ActivityType;
import az.ailab.lib.common.security.model.enums.Permission;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.security.model.enums.RoleType;
import java.util.Map;

public class TestConstant {

    public static final String ADMIN = "ADMIN";
    public static final Map<String, String> PERMISSIONS = Map.of(
            Permission.ORDER_READ.name(), PermissionLevel.INSTITUTION.name(),
            Permission.USER_EDIT.name(), PermissionLevel.PERSONAL.name(),
            Permission.USER_READ.name(), PermissionLevel.INSTITUTION.name()
    );

    public static final String SUB = "abcd123";
    public static final long IAT = 1625097600;
    public static final long EXP = 1625184000;
    public static final long USER_ID = 1;
    public static final String FIRST_NAME = "Farid";
    public static final String LAST_NAME = "Tahmazov";
    public static final String USER_EMAIL = "farid.tahmazov@ailab.az";
    public static final String USER_RANK = "Software Backend engineer";
    public static final String USER_POSITION = "Big specialist";
    public static final long USER_ROLE_ID = 1;
    public static final String USER_ROLE_NAME = "ADMIN";
    public static final String ROLE_TYPE = RoleType.DIRECTORATE_ADMIN.name();
    public static final long USER_INSTITUTION_ID = 1;
    public static final String USER_INSTITUTION_NAME = "FBI";
    public static final String INSTITUTION_ACTIVITY_TYPE = ActivityType.BOTH.name();
    public static final String RANK_TYPE = "military";
    public static final long USER_DIRECT_STRUCTURE_ID = 4;
    public static final String USER_STRUCTURE_PATH = "1/2/3/4";

    public static final long USER_DIRECTORATE_ID = 2;
    public static final String USER_DIRECTORATE_NAME = "sub-1";
    public static final String DIRECTORATE_ACTIVITY_TYPE = ActivityType.PROVIDER.name();

    public static final String JSON_PAYLOAD = """
            {
                 "sub": "abcd123",
                 "iat": 1625097600,
                 "exp": 1625184000,
                 "user": {
                     "id": 1,
                     "firstName": "Farid",
                     "lastName": "Tahmazov",
                     "email": "farid.tahmazov@ailab.az",
                     "rank": "Software Backend engineer",
                     "position": "Big specialist",
                     "directStructureId": 4,
                     "role": {
                         "id": 1,
                         "name": "ADMIN",
                         "type": "DIRECTORATE_ADMIN",
                         "permissions": {
                             "USER_READ": "INSTITUTION",
                             "USER_EDIT": "PERSONAL",
                             "ORDER_READ": "INSTITUTION"
                         }
                     }
                 },
                 "institution": {
                     "id": 1,
                     "name": "FBI",
                     "activityType": "BOTH",
                     "rankType": "military",
                     "path": "1/2/3/4",
                     "directorate": {
                             "id": 2,
                             "name": "sub-1",
                             "activityType": "PROVIDER"
                     }
                 }
             }
           \s""";

}
