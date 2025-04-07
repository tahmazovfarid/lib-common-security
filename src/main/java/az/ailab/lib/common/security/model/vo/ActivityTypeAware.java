package az.ailab.lib.common.security.model.vo;

import az.ailab.lib.common.security.model.enums.ActivityType;
import az.ailab.lib.common.util.EnumUtil;

public interface ActivityTypeAware {

    String activityType();

    default ActivityType getActivityType() {
        return EnumUtil.getOptEnumConstant(ActivityType.class, activityType())
                .orElseThrow(() -> new IllegalArgumentException("Invalid activity type: " + activityType()));
    }

}
