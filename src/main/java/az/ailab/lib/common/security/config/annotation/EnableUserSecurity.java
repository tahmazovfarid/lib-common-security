package az.ailab.lib.common.security.config.annotation;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import az.ailab.lib.common.security.provider.UserTokenProvider;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

@Target(TYPE)
@Retention(RUNTIME)
@Documented
@Import(UserTokenProvider.class)
public @interface EnableUserSecurity {

}