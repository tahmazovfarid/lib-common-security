package az.ailab.lib.common.security.error;

import az.ailab.lib.common.dto.response.ResponseWrapper;
import az.ailab.lib.common.error.CommonErrorHandler;
import az.ailab.lib.common.error.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class SecurityErrorHandler extends CommonErrorHandler {

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseWrapper<ErrorResponse> handleAccessDeniedException(final AccessDeniedException ex) {
        log.error("Forbidden, message: {}", ex.getMessage());
        final ErrorResponse response = ErrorResponse.build(HttpStatus.FORBIDDEN, ex.getMessage());

        return ResponseWrapper.error(response);
    }

}