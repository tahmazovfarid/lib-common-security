package az.ailab.lib.common.security.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import az.ailab.lib.common.security.contant.TestConstant;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TokenPayloadTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    void setup() {
        objectMapper = new ObjectMapper();
    }

    @Test
    void fromJsonNode_fullValidPayload() throws JsonProcessingException {
        JsonNode jsonNode = objectMapper.readTree(TestConstant.JSON_PAYLOAD);

        TokenPayload payload = TokenPayload.fromJsonNode(jsonNode);

        // Assert basic fields
        assertThat(payload.getSubject()).isEqualTo(TestConstant.SUB);
        assertThat(payload.getIssuedAt()).isEqualTo(TestConstant.IAT);
        assertThat(payload.getExpirationTime()).isEqualTo(TestConstant.EXP);
        assertThat(payload.getUserId()).isEqualTo(TestConstant.USER_ID);
        assertThat(payload.getFullName()).isEqualTo(TestConstant.USER_FULL_NAME);
        assertThat(payload.getEmail()).isEqualTo(TestConstant.USER_EMAIL);
        assertThat(payload.getRank()).isEqualTo(TestConstant.USER_RANK);
        assertThat(payload.getPosition()).isEqualTo(TestConstant.USER_POSITION);

        // Assert role information
        assertThat(payload.getRoleId()).isEqualTo(TestConstant.USER_ROLE_ID);
        assertThat(payload.getRoleName()).isEqualTo(TestConstant.USER_ROLE_NAME);
        assertThat(payload.isExecutor()).isEqualTo(TestConstant.USER_ROLE_IS_EXECUTOR);
        assertThat(payload.getPermissions()).isEqualTo(TestConstant.USER_ROLE_PERMISSIONS);

        // Assert organization information
        assertThat(payload.getOrganizationId()).isEqualTo(TestConstant.USER_ORGANIZATION_ID);
        assertThat(payload.getOrganizationName()).isEqualTo(TestConstant.USER_ORGANIZATION_NAME);
        assertThat(payload.getOrganizationPrivilege()).isEqualTo(TestConstant.USER_ORGANIZATION_PRIVILEGE);
        assertThat(payload.getDirectOrganizationId()).isEqualTo(TestConstant.USER_DIRECT_ORGANIZATION_ID);
        assertThat(payload.getOrganizationPath()).isEqualTo(TestConstant.USER_ORGANIZATION_PATH);

        // Assert organization hierarchy
        assertThat(payload.getOrganizationHierarchy())
                .hasSize(3)
                .isEqualTo(TestConstant.USER_ORGANIZATION_HIERARCHY);
    }

    @Test
    void fromJsonNode_nullPayload() {
        assertThatThrownBy(() -> TokenPayload.fromJsonNode(null))
                .isInstanceOf(NullPointerException.class);
    }

}
