package az.ailab.lib.common.security.filter;

import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.security.provider.AbstractTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final AbstractTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(@NonNull final HttpServletRequest request,
                                    @NonNull final HttpServletResponse response,
                                    @NonNull final FilterChain filterChain) throws ServletException, IOException {
        final String jwt = resolveToken(request);

        if (StringUtils.isNotBlank(jwt)) {
            buildAuthentication(jwt)
                    .ifPresent(authentication -> SecurityContextHolder.getContext()
                            .setAuthentication(authentication));
        }

        filterChain.doFilter(request, response);
    }

    public Optional<Authentication> buildAuthentication(final String jwt) {
        return tokenProvider.extractPayload(jwt)
                .map(tokenProvider::buildAuthentication);
    }

    private String resolveToken(final HttpServletRequest request) {
        final String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        return extractBearerToken(bearerToken);
    }

    private String extractBearerToken(final String bearerToken) {
        if (StringUtils.isNotEmpty(bearerToken) && bearerToken.startsWith(SecurityConstant.BEARER)) {
            log.debug("Authorization token is received: {}", bearerToken);
            return bearerToken.substring(SecurityConstant.BEARER.length());
        } else {
            log.debug("There is not found any token. Request received from anonymous user.");
        }

        return null;
    }

}