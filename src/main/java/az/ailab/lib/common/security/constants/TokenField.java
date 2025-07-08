package az.ailab.lib.common.security.constants;

/**
 * Constants for JSON field names used in token payload parsing.
 * <p>Provides a single source of truth for all keys passed to JsonNode.path(...).</p>
 *
 * @since 1.0
 */
public final class TokenField {

    private TokenField() {
        // utility class
    }

    // Basic JWT claims
    public static final String SUB = "sub";
    public static final String IAT = "iat";
    public static final String EXP = "exp";

    // User node and fields
    public static final String USER = "user";
    public static final String ID = "id";
    public static final String FIRST_NAME = "firstName";
    public static final String LAST_NAME = "lastName";
    public static final String EMAIL = "email";
    public static final String RANK = "rank";
    public static final String POSITION = "position";
    public static final String STRUCTURE_ID = "structureId";

    // Role node and fields
    public static final String ROLE = "role";
    public static final String NAME = "name";
    public static final String TYPE = "type";
    public static final String PERMISSIONS = "permissions";

    // Institution node and fields
    public static final String INSTITUTION = "institution";
    public static final String ACTIVITY_TYPE = "activityType";
    public static final String RANK_TYPE = "rankType";
    public static final String PATH = "path";

    // Directorate node and fields
    public static final String DIRECTORATE = "directorate";

}

