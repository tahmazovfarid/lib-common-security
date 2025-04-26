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
 * an instance of this class.</p>
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
        payload.subject = jsonNode.path(TokenField.SUB).asText();
        payload.issuedAt = jsonNode.path(TokenField.IAT).asLong();
        payload.expirationTime = jsonNode.path(TokenField.EXP).asLong();
    }

    /**
     * Extracts user-specific fields and delegates role extraction.
     *
     * @param userNode the JSON node under the "user" key
     * @param payload  the target payload object to populate
     */
    private static void extractUserAndRoleInfo(final JsonNode userNode, final TokenPayload payload) {
        payload.userId = userNode.path(TokenField.ID).asLong();
        payload.firstName = userNode.path(TokenField.FIRST_NAME).asText();
        payload.lastName = userNode.path(TokenField.LAST_NAME).asText();
        payload.email = userNode.path(TokenField.EMAIL).asText();
        payload.rank = userNode.path(TokenField.RANK).asText();
        payload.position = userNode.path(TokenField.POSITION).asText();
        payload.structureId = userNode.path(TokenField.DIRECT_STRUCTURE_ID).asLong();

        extractRoleInfo(userNode.path(TokenField.ROLE), payload);
    }

    /**
     * Extracts role fields and permission map.
     *
     * @param roleNode the JSON node under the "role" key
     * @param payload  the target payload object to populate
     */
    private static void extractRoleInfo(final JsonNode roleNode, final TokenPayload payload) {
        payload.roleId = roleNode.path(TokenField.ID).asLong();
        payload.roleName = roleNode.path(TokenField.NAME).asText();
        payload.roleType = roleNode.path(TokenField.TYPE).asText();
        payload.permissions = extractArrayAsMap(roleNode.path(TokenField.PERMISSIONS));
    }

    /**
     * Extracts institution-related fields and delegates directorate extraction.
     *
     * @param instNode the JSON node under the "institution" key
     * @param payload  the target payload object to populate
     */
    private static void extractInstitutionInfo(final JsonNode instNode, final TokenPayload payload) {
        payload.institutionId = instNode.path(TokenField.ID).asInt();
        payload.institutionName = instNode.path(TokenField.NAME).asText();
        payload.institutionActivityType = instNode.path(TokenField.ACTIVITY_TYPE).asText();
        payload.institutionRankType = instNode.path(TokenField.RANK_TYPE).asText();
        payload.structurePath = instNode.path(TokenField.PATH).asText();
        extractDirectorate(instNode.path(TokenField.DIRECTORATE), payload);
    }

    /**
     * Optionally extracts directorate fields if present.
     *
     * @param directorateNode the JSON node under the "directorate" key (maybe missing)
     * @param payload         the target payload object to populate
     */
    private static void extractDirectorate(final JsonNode directorateNode, final TokenPayload payload) {
        if (directorateNode != null && !directorateNode.isNull() && !directorateNode.isMissingNode()) {
            payload.directorateId = directorateNode.path(TokenField.ID).asLong();
            payload.directorateName = directorateNode.path(TokenField.NAME).asText();
            payload.directorateActivityType = directorateNode.path(TokenField.ACTIVITY_TYPE).asText();
        }
    }

    /**
     * Converts a JSON object node into a Map of its fields to text values.
     *
     * @param jsonNode the JSON node representing an object or map
     * @return a Map where each key is the field name and each value is the node's text
     */
    private static Map<String, String> extractArrayAsMap(final JsonNode jsonNode) {
        final Map<String, String> map = new HashMap<>();
        jsonNode.fields().forEachRemaining(
                entry -> map.put(entry.getKey(), entry.getValue().asText())
        );
        return map;
    }

}