package az.ailab.lib.common.security.model.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum PermissionEnum {

    // User management
    USER_READ,
    USER_CREATE,
    USER_EDIT,
    USER_DELETE,

    // Role & Permission management
    ROLE_READ,
    ROLE_CREATE,
    ROLE_EDIT,
    ROLE_DELETE,

    // Structure Management
    STRUCTURE_READ,
    STRUCTURE_CREATE,
    STRUCTURE_EDIT,
    STRUCTURE_DELETE,

    // Structural Unit management
    STRUCTURAL_UNIT_READ,
    STRUCTURAL_UNIT_CREATE,
    STRUCTURAL_UNIT_EDIT,
    STRUCTURAL_UNIT_DELETE,

    // Reporting Management
    REPORTING_READ,

    // Support Management
    SUPPORT_READ,
    SUPPORT_CREATE,
    SUPPORT_EDIT,
    SUPPORT_DELETE,

    // Personal information management
    PERSONAL_EDIT,

    // Request submission management
    REQUEST_READ,
    REQUEST_CREATE,
    REQUEST_EDIT,

    // Inquiry receiving management
    INQUIRY_RECEIVING_READ,
    INQUIRY_RECEIVING_CREATE,
    INQUIRY_RECEIVING_ASSIGN,
    INQUIRY_RECEIVING_APPROVE,

    // Order management
    ORDER_READ,
    ORDER_CREATE,
    ORDER_EDIT,

    // Flow management
    FLOW_READ,
    FLOW_CREATE,
    FLOW_EDIT,
    INQUIRY_APPROVE;

    @JsonValue
    public String toValue() {
        return name();
    }

}
