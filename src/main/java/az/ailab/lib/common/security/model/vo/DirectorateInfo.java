package az.ailab.lib.common.security.model.vo;

public record DirectorateInfo(Long id,
                              String name,
                              String activityType) implements ActivityTypeAware {

}
