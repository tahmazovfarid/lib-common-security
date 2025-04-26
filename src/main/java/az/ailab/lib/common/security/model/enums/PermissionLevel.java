package az.ailab.lib.common.security.model.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum PermissionLevel {

    PERSONAL,
    STRUCTURE,
    DIRECTORATE,
    INSTITUTION,
    SYSTEM;

    @JsonValue
    public String toValue() {
        return name();
    }

}
