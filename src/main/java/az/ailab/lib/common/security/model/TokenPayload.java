package az.ailab.lib.common.security.model;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;

@Data
public class TokenPayload {

    private String subject;
    private Long issuedAt;
    private Long expirationTime;

    private Long userId;
    private String firstName;
    private String lastName;
    private String email;

    private String rank;
    private String position;

    private Long roleId;
    private String roleName;
    private String roleType;
    private Map<String, String> permissions = new HashMap<>();

    private Integer institutionId;
    private String institutionName;
    private String institutionActivityType;
    private String structurePath;
    private Long directStructureId;

    private Long directorateId;
    private String directorateName;
    private String directorateActivityType;

    private JsonNode payloadNode;

    public static TokenPayload fromJsonNode(final JsonNode jsonNode) {
        TokenPayload payload = new TokenPayload();
        payload.payloadNode = jsonNode;

        extractBasicFields(jsonNode, payload);

        extractUserAndRoleInfo(jsonNode.path("user"), payload);

        extractInstitutionInfo(jsonNode.path("institution"), payload);

        return payload;
    }

    private static void extractBasicFields(final JsonNode jsonNode, final TokenPayload payload) {
        payload.subject = jsonNode.path("sub").asText();
        payload.issuedAt = jsonNode.path("iat").asLong();
        payload.expirationTime = jsonNode.path("exp").asLong();
    }

    private static void extractUserAndRoleInfo(final JsonNode userNode, final TokenPayload payload) {
        payload.userId = userNode.path("id").asLong();
        payload.firstName = userNode.path("firstName").asText();
        payload.lastName = userNode.path("lastName").asText();
        payload.email = userNode.path("email").asText();
        payload.rank = userNode.path("rank").asText();
        payload.position = userNode.path("position").asText();
        payload.directStructureId = userNode.path("directStructureId").asLong();

        extractRoleInfo(userNode.path("role"), payload);
    }

    private static void extractRoleInfo(final JsonNode roleNode, final TokenPayload payload) {
        payload.roleId = roleNode.path("id").asLong();
        payload.roleName = roleNode.path("name").asText();
        payload.roleType = roleNode.path("type").asText();
        payload.permissions = extractArrayAsMap(roleNode.path("permissions"));
    }

    private static void extractInstitutionInfo(final JsonNode instNode, final TokenPayload payload) {
        payload.institutionId = instNode.path("id").asInt();
        payload.institutionName = instNode.path("name").asText();
        payload.institutionActivityType = instNode.path("activityType").asText();
        payload.structurePath = instNode.path("path").asText();
        extractDirectorate(instNode.path("directorate"), payload);
    }

    private static void extractDirectorate(final JsonNode directorateNode, final TokenPayload payload) {
        if (directorateNode != null && !directorateNode.isNull() && !directorateNode.isMissingNode()) {
            payload.directorateId = directorateNode.path("id").asLong();
            payload.directorateName = directorateNode.path("name").asText();
            payload.directorateActivityType = directorateNode.path("activityType").asText();
        }
    }

    private static Map<String, String> extractArrayAsMap(final JsonNode jsonNode) {
        final Map<String, String> map = new HashMap<>();
        jsonNode.fields().forEachRemaining(
                entry -> map.put(entry.getKey(), entry.getValue().asText())
        );
        return map;
    }

}