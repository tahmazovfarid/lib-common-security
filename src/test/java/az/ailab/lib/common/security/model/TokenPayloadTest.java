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
        assertThat(payload.getFirstName()).isEqualTo(TestConstant.FIRST_NAME);
        assertThat(payload.getLastName()).isEqualTo(TestConstant.LAST_NAME);
        assertThat(payload.getEmail()).isEqualTo(TestConstant.USER_EMAIL);
        assertThat(payload.getRank()).isEqualTo(TestConstant.USER_RANK);
        assertThat(payload.getPosition()).isEqualTo(TestConstant.USER_POSITION);
        assertThat(payload.getDirectStructureId()).isEqualTo(TestConstant.USER_DIRECT_STRUCTURE_ID);

        // Assert role information
        assertThat(payload.getRoleId()).isEqualTo(TestConstant.USER_ROLE_ID);
        assertThat(payload.getRoleName()).isEqualTo(TestConstant.USER_ROLE_NAME);
        assertThat(payload.getRoleType()).isEqualTo(TestConstant.ROLE_TYPE);
        assertThat(payload.getPermissions()).isEqualTo(TestConstant.PERMISSIONS);

        // Assert institution information
        assertThat(payload.getInstitutionId()).isEqualTo(TestConstant.USER_INSTITUTION_ID);
        assertThat(payload.getInstitutionName()).isEqualTo(TestConstant.USER_INSTITUTION_NAME);
        assertThat(payload.getInstitutionActivityType()).isEqualTo(TestConstant.INSTITUTION_ACTIVITY_TYPE);
        assertThat(payload.getStructurePath()).isEqualTo(TestConstant.USER_STRUCTURE_PATH);

        // Assert directorate information
        assertThat(payload.getDirectorateId()).isEqualTo(TestConstant.USER_DIRECTORATE_ID);
        assertThat(payload.getDirectorateName()).isEqualTo(TestConstant.USER_DIRECTORATE_NAME);
        assertThat(payload.getDirectorateActivityType()).isEqualTo(TestConstant.DIRECTORATE_ACTIVITY_TYPE);

    }

    @Test
    void fromJsonNode_nullPayload() {
        assertThatThrownBy(() -> TokenPayload.fromJsonNode(null))
                .isInstanceOf(NullPointerException.class);
    }

}
