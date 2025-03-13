package az.ailab.lib.common.security.model;

import java.util.List;

public record UserOrganization(long id,
                               String name,
                               String privilege,
                               long directOrganizationId,
                               List<String> path,
                               List<OrganizationLevel> hierarchy) {

}
