package az.ailab.lib.common.security.model.enums;

public enum Permission {

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
    SUPPORT_APPROVE,
    SUPPORT_DELETE,

    // Personal information management
    PERSONAL_READ,
    PERSONAL_CREATE,
    PERSONAL_EDIT,

    // Request submission management
    REQUEST_READ,
    REQUEST_CREATE,
    REQUEST_EDIT,
    REQUEST_APPROVE,

    // Inquiry receiving management
    INQUIRY_RECEIVING_READ,
    INQUIRY_RECEIVING_CREATE,
    INQUIRY_RECEIVING_ASSIGN,
    INQUIRY_RECEIVING_APPROVE,

    // Order management
    ORDER_READ,
    ORDER_CREATE,
    ORDER_ASSIGN,
    ORDER_APPROVE,

    // Inquiry management
    INQUIRY_READ,
    INQUIRY_CREATE,
    INQUIRY_ASSIGN,
    INQUIRY_APPROVE,

}
