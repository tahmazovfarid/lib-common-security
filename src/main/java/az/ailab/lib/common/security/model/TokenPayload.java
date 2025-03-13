package az.ailab.lib.common.security.model;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import lombok.Data;

@Data
public class TokenPayload {

    private String subject;
    private long issuedAt;
    private long expirationTime;

    private long userId;
    private String fullName;
    private String email;

    private String rank;
    private String position;

    private long roleId;
    private String roleName;
    private boolean isExecutor;
    private Set<String> permissions = new HashSet<>();

    private long organizationId;
    private String organizationName;
    private String organizationPrivilege;
    private long directOrganizationId;
    private List<String> organizationPath = new ArrayList<>();
    private List<OrganizationLevel> organizationHierarchy = new ArrayList<>();

    private JsonNode payloadNode;

    public static TokenPayload fromJsonNode(JsonNode jsonNode) {
        TokenPayload payload = new TokenPayload();
        payload.payloadNode = jsonNode;

        extractBasicFields(jsonNode, payload);

        extractUserAndRoleInfo(jsonNode.path("user"), payload);

        extractOrganizationInfo(jsonNode.path("organization"), payload);

        return payload;
    }

    private static void extractBasicFields(JsonNode jsonNode, TokenPayload payload) {
        payload.subject = jsonNode.path("sub").asText();
        payload.issuedAt = jsonNode.path("iat").asLong();
        payload.expirationTime = jsonNode.path("exp").asLong();
    }

    private static void extractUserAndRoleInfo(JsonNode userNode, TokenPayload payload) {
        payload.userId = userNode.path("id").asLong();
        payload.fullName = userNode.path("fullname").asText();
        payload.email = userNode.path("email").asText();
        payload.rank = userNode.path("rank").asText();
        payload.position = userNode.path("position").asText();

        JsonNode roleNode = userNode.path("role");
        payload.roleId = roleNode.path("id").asLong();
        payload.roleName = roleNode.path("name").asText();
        payload.isExecutor = roleNode.path("isExecutor").asBoolean();
        payload.permissions = extractArrayAsStringSet(roleNode.path("permissions"));
    }

    private static void extractOrganizationInfo(JsonNode orgNode, TokenPayload payload) {
        payload.organizationId = orgNode.path("id").asLong();
        payload.organizationName = orgNode.path("name").asText();
        payload.organizationPrivilege = orgNode.path("privilege").asText();
        payload.directOrganizationId = orgNode.path("directOrganizationId").asLong();
        payload.organizationPath = extractArrayAsStringList(orgNode.path("path"));
        payload.organizationHierarchy = extractOrganizationHierarchy(orgNode.path("hierarchy"));
    }

    private static Set<String> extractArrayAsStringSet(JsonNode arrayNode) {
        if (!arrayNode.isArray()) {
            return new HashSet<>();
        }

        return StreamSupport.stream(arrayNode.spliterator(), false)
                .map(JsonNode::asText)
                .collect(Collectors.toSet());
    }

    private static List<String> extractArrayAsStringList(JsonNode arrayNode) {
        if (!arrayNode.isArray()) {
            return new ArrayList<>();
        }

        return StreamSupport.stream(arrayNode.spliterator(), false)
                .map(JsonNode::asText)
                .collect(Collectors.toList());
    }

    private static List<OrganizationLevel> extractOrganizationHierarchy(JsonNode hierarchyNode) {
        if (!hierarchyNode.isArray()) {
            return new ArrayList<>();
        }

        return StreamSupport.stream(hierarchyNode.spliterator(), false)
                .map(node -> new OrganizationLevel(
                        node.path("id").asLong(),
                        node.path("name").asText(),
                        node.path("privilege").asText(),
                        node.path("level").asInt(),
                        node.path("parentId").asLong()
                )).collect(Collectors.toList());
    }

}