package az.ailab.lib.common.security.model;

import az.ailab.lib.common.security.model.enums.ActivityType;
import az.ailab.lib.common.util.EnumUtil;
import java.util.List;

public record UserOrganization(long id,
                               String name,
                               String activityType,
                               long directOrganizationId,
                               List<String> path,
                               List<OrganizationLevel> hierarchy) {

    public ActivityType getActivityType() {
        return EnumUtil.getEnumConstant(ActivityType.class, activityType());
    }

}
