package az.ailab.lib.common.security.model;

import java.util.Set;

public record UserRole(long id,
                       String name,
                       boolean isExecutor,
                       Set<String> permissions) {

}
