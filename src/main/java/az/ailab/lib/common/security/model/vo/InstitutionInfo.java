package az.ailab.lib.common.security.model.vo;

import az.ailab.lib.common.security.model.enums.RankType;
import az.ailab.lib.common.util.EnumUtil;

public record InstitutionInfo(Integer id,
                              String name,
                              String activityType,
                              String rankType,
                              String path,
                              DirectorateInfo directorateInfo) implements ActivityTypeAware {

    public RankType getRankType() {
        return EnumUtil.getOptEnumConstant(RankType.class, rankType())
                .orElseThrow(() -> new IllegalArgumentException("Invalid rank type: " + rankType()));
    }

}
