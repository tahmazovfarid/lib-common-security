package az.ailab.lib.common.security.model.vo;

import az.ailab.lib.common.security.model.enums.PermissionEnum;
import az.ailab.lib.common.security.model.enums.PermissionLevel;
import az.ailab.lib.common.security.model.enums.RoleType;
import java.util.Map;

public record UserRole(Long id,
                       String name,
                       RoleType type,
                       Map<PermissionEnum, PermissionLevel> permissions) {

}
