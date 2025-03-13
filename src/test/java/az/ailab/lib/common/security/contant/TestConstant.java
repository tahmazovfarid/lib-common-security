package az.ailab.lib.common.security.contant;

import az.ailab.lib.common.security.model.OrganizationLevel;
import java.util.List;
import java.util.Set;

public class TestConstant {

    public static final String ADMIN = "ADMIN";
    public static final String USER_READ = "USER_READ";
    public static final String USER_WRITE = "USER_WRITE";
    public static final Set<String> PERMISSIONS = Set.of(USER_READ, USER_WRITE);

    public static final String SUB = "abcd123";
    public static final long IAT = 1625097600;
    public static final long EXP = 1625184000;
    public static final long USER_ID = 1;
    public static final String USER_FULL_NAME = "Tahmazov Farid";
    public static final String USER_EMAIL = "farid.tahmazov@ailab.az";
    public static final String USER_RANK = "Software Backend engineer";
    public static final String USER_POSITION = "Big specialist";
    public static final long USER_ROLE_ID = 1;
    public static final String USER_ROLE_NAME = "ADMIN";
    public static final boolean USER_ROLE_IS_EXECUTOR = true;
    public static final Set<String> USER_ROLE_PERMISSIONS = PERMISSIONS;
    public static final long USER_ORGANIZATION_ID = 1;
    public static final String USER_ORGANIZATION_NAME = "FBI";
    public static final String USER_ORGANIZATION_PRIVILEGE = "CAN_ORDER_SEND_AND_RECEIVE";
    public static final long USER_DIRECT_ORGANIZATION_ID = 4;
    public static final List<String> USER_ORGANIZATION_PATH = List.of("FBI", "sub-1", "sub-2", "sub-3");
    public static final List<OrganizationLevel> USER_ORGANIZATION_HIERARCHY = List.of(
            new OrganizationLevel(2, "sub-1", "CAN_ORDER_SEND", 1, 1),
            new OrganizationLevel(3, "sub-2", "CAN_ORDER_SEND", 2, 2),
            new OrganizationLevel(4, "sub-3", "CAN_ORDER_SEND", 3, 3)
    );

    public static final String JSON_PAYLOAD = """
            {
                "sub": "abcd123",
                "iat": 1625097600,
                "exp": 1625184000,
                "user": {
                    "id": 1,
                    "fullname": "Tahmazov Farid",
                    "email": "farid.tahmazov@ailab.az",
                    "rank": "Software Backend engineer",
                    "position": "Big specialist",
                    "role": {
                        "id": 1,
                        "name": "ADMIN",
                        "isExecutor": true,
                        "permissions": ["USER_READ", "USER_WRITE"]
                    }
                },
                "organization": {
                    "id": 1,
                    "name": "FBI",
                    "privilege": "CAN_ORDER_SEND_AND_RECEIVE",
                    "directOrganizationId": 4,
                    "path": ["FBI", "sub-1", "sub-2", "sub-3"],
                    "hierarchy": [
                        {
                            "id": 2,
                            "name": "sub-1",
                            "privilege": "CAN_ORDER_SEND",
                            "level": 1,
                            "parentId": 1
                        },
                        {
                            "id": 3,
                            "name": "sub-2",
                            "privilege": "CAN_ORDER_SEND",
                            "level": 2,
                            "parentId": 2
                        },
                        {
                            "id": 4,
                            "name": "sub-3",
                            "privilege": "CAN_ORDER_SEND",
                            "level": 3,
                            "parentId": 3
                        }
                    ]
                }
            }
            """;

}
