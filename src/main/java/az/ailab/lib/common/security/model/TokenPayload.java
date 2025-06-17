package az.ailab.lib.common.security.model;

import az.ailab.lib.common.security.constants.TokenField;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;

/**
 * Represents the structured payload extracted from a decoded JWT.
 * <p>
 * This value object provides typed access to standard JWT claims (subject, issuedAt, exp)
 * as well as nested user, role, institution, and directorate details as defined in the
 * token's JSON structure. Use {@link #fromJsonNode(JsonNode)} to parse a payload tree into
 * an instance of this class. </p>
 * <p>
 * Required fields are validated during parsing. Optional fields may be null.
 *
 * @author tahmazovfarid
 * @since 1.0
 */
@Data
public class TokenPayload {

    // Basic JWT claims
    private String subject;
    private Long issuedAt;
    private Long expirationTime;

    // User details
    private Long userId;
    private String firstName;
    private String lastName;
    private String userType;
    private String email;
    private String rank;
    private String position;
    private Long structureId;

    // Role details
    private Long roleId;
    private String roleName;
    private String roleType;
    private Map<String, String> permissions = new HashMap<>();

    // Institution details
    private Integer institutionId;
    private String institutionName;
    private String institutionActivityType;
    private String institutionRankType;
    private String structurePath;

    // Directorate details (optional)
    private Long directorateId;
    private String directorateName;
    private String directorateActivityType;

    // Raw JSON node for advanced or custom parsing needs
    private JsonNode payloadNode;

    /**
     * Factory method to create a {@link TokenPayload} from a parsed JWT payload node.
     * <p>
     * Extracts basic claims, then nested user, role, institution, and directorate sections.
     * </p>
     *
     * @param jsonNode the root JSON node of the JWT payload
     * @return a populated {@link TokenPayload} instance
     * @throws IllegalArgumentException if required fields are missing or invalid
     */
    public static TokenPayload fromJsonNode(final JsonNode jsonNode) {
        TokenPayload payload = new TokenPayload();
        payload.payloadNode = jsonNode;

        extractBasicFields(jsonNode, payload);
        extractUserAndRoleInfo(jsonNode.path(TokenField.USER), payload);
        extractInstitutionInfo(jsonNode.path(TokenField.INSTITUTION), payload);

        return payload;
    }

    /**
     * Extracts the standard JWT claims: subject (sub), issuedAt (iat), and expirationTime (exp).
     *
     * @param jsonNode the JWT payload node
     * @param payload  the target payload object to populate
     */
    private static void extractBasicFields(final JsonNode jsonNode, final TokenPayload payload) {
        payload.subject = requireNonNull(jsonNode, TokenField.SUB);
        payload.issuedAt = requireNonNullLong(jsonNode, TokenField.IAT);
        payload.expirationTime = requireNonNullLong(jsonNode, TokenField.EXP);
    }

    /**
     * Extracts user-specific fields and delegates role extraction.
     *
     * @param userNode the JSON node under the "user" key
     * @param payload  the target payload object to populate
     */
    private static void extractUserAndRoleInfo(final JsonNode userNode, final TokenPayload payload) {
        payload.userId = requireNonNullLong(userNode, TokenField.ID);
        payload.firstName = requireNonNull(userNode, TokenField.FIRST_NAME);
        payload.lastName = requireNonNull(userNode, TokenField.LAST_NAME);
        payload.email = requireNonNull(userNode, TokenField.EMAIL);
        payload.userType = requireNonNull(userNode, TokenField.TYPE);
        payload.rank = getNullable(userNode, TokenField.RANK);
        payload.position = getNullable(userNode, TokenField.POSITION);

        payload.structureId = getNullableLong(userNode, TokenField.DIRECT_STRUCTURE_ID);

        extractRoleInfo(userNode.path(TokenField.ROLE), payload);
    }

    /**
     * Extracts role fields and permission map.
     *
     * @param roleNode the JSON node under the "role" key
     * @param payload  the target payload object to populate
     */
    private static void extractRoleInfo(final JsonNode roleNode, final TokenPayload payload) {
        payload.roleId = requireNonNullLong(roleNode, TokenField.ID);
        payload.roleName = requireNonNull(roleNode, TokenField.NAME);
        payload.roleType = requireNonNull(roleNode, TokenField.TYPE);
        payload.permissions = extractArrayAsMap(roleNode.path(TokenField.PERMISSIONS));
    }

    /**
     * Extracts institution-related fields and delegates directorate extraction.
     *
     * @param instNode the JSON node under the "institution" key
     * @param payload  the target payload object to populate
     */
    private static void extractInstitutionInfo(final JsonNode instNode, final TokenPayload payload) {
        payload.institutionId = getNullableInt(instNode, TokenField.ID);
        payload.institutionName = getNullable(instNode, TokenField.NAME);
        payload.institutionActivityType = getNullable(instNode, TokenField.ACTIVITY_TYPE);
        payload.institutionRankType = getNullable(instNode, TokenField.RANK_TYPE);
        payload.structurePath = getNullable(instNode, TokenField.PATH);

        extractDirectorate(instNode.path(TokenField.DIRECTORATE), payload);
    }

    /**
     * Optionally extracts directorate fields if present.
     *
     * @param directorateNode the JSON node under the "directorate" key (maybe missing)
     * @param payload         the target payload object to populate
     */
    private static void extractDirectorate(final JsonNode directorateNode, final TokenPayload payload) {
        payload.directorateId = getNullableLong(directorateNode, TokenField.ID);
        payload.directorateName = getNullable(directorateNode, TokenField.NAME);
        payload.directorateActivityType = getNullable(directorateNode, TokenField.ACTIVITY_TYPE);
    }

    /**
     * Converts a JSON object node into a Map of its fields to text values.
     *
     * @param jsonNode the JSON node representing an object or map
     * @return a Map where each key is the field name and each value is the node's text
     */
    private static Map<String, String> extractArrayAsMap(final JsonNode jsonNode) {
        final Map<String, String> map = new HashMap<>();
        jsonNode.fields()
                .forEachRemaining(entry -> map.put(entry.getKey(), entry.getValue().asText()));
        return map;
    }

    // --- Helper methods for safe extraction ---
    private static String requireNonNull(JsonNode node, String field) {
        JsonNode valueNode = node.path(field);
        if (valueNode.isMissingNode() || valueNode.isNull() || valueNode.asText().isBlank()) {
            throw new IllegalArgumentException("Missing or null required field: " + field);
        }
        return valueNode.asText();
    }

    private static Long requireNonNullLong(JsonNode node, String field) {
        JsonNode valueNode = node.path(field);
        if (valueNode.isMissingNode() || valueNode.isNull()) {
            throw new IllegalArgumentException("Missing or null required long field: " + field);
        }
        return valueNode.asLong();
    }

    private static String getNullable(JsonNode node, String field) {
        JsonNode valueNode = node.path(field);
        return (valueNode.isMissingNode() || valueNode.isNull()) ? null : valueNode.asText();
    }

    private static Long getNullableLong(JsonNode node, String field) {
        JsonNode valueNode = node.path(field);
        return (valueNode.isMissingNode() || valueNode.isNull()) ? null : valueNode.asLong();
    }

    private static Integer getNullableInt(JsonNode node, String field) {
        JsonNode valueNode = node.path(field);
        return (valueNode.isMissingNode() || valueNode.isNull()) ? null : valueNode.asInt();
    }

}