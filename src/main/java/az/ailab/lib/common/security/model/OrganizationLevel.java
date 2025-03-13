package az.ailab.lib.common.security.model;

public record OrganizationLevel(long id,
                                String name,
                                String privilege,
                                int level,
                                long parentId) {

}
