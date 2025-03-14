package az.ailab.lib.common.security.model;

import az.ailab.lib.common.security.model.enums.ActivityType;
import az.ailab.lib.common.util.EnumUtil;

public record OrganizationLevel(long id,
                                String name,
                                String activityType,
                                int level,
                                long parentId) {

    public ActivityType getActivityType() {
        return EnumUtil.getEnumConstant(ActivityType.class, activityType());
    }

}
