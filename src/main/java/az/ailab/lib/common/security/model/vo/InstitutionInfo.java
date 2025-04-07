package az.ailab.lib.common.security.model.vo;

public record InstitutionInfo(Integer id,
                              String name,
                              String activityType,
                              String rankType,
                              String path,
                              DirectorateInfo directorateInfo) implements ActivityTypeAware {

}
