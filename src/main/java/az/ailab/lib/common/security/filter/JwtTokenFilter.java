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
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final AbstractTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String jwt = resolveToken(request);

        if (StringUtils.isNotBlank(jwt)) {
            buildAuthentication(jwt)
                    .ifPresent(authentication -> SecurityContextHolder.getContext()
                            .setAuthentication(authentication));
        }

        filterChain.doFilter(request, response);
    }

    public Optional<Authentication> buildAuthentication(String jwt) {
        return tokenProvider.extractPayload(jwt)
                .map(tokenProvider::buildAuthentication);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        return extractBearerToken(bearerToken);
    }

    private String extractBearerToken(String bearerToken) {
        if (StringUtils.isNotEmpty(bearerToken) && bearerToken.startsWith(SecurityConstant.BEARER)) {
            return bearerToken.substring(SecurityConstant.BEARER.length());
        }

        return null;
    }

}