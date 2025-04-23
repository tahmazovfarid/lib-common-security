package az.ailab.lib.common.security.util;

import az.ailab.lib.common.security.constants.SecurityConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * Utility methods for parsing, validating, and extracting data from JWTs
 * using the JJWT library.
 * <p>
 * All methods assume the token is signed with an HMAC secret (HS256+).
 * The secretKey parameter must be a Base64‑encoded string.
 * </p>
 */
public final class JwtUtil {

    private JwtUtil() { /* utility class */ }

    /**
     * Parses and verifies the given JWT, returning the full {@link Jws} wrapper,
     * which contains header, body (claims), and signature.
     *
     * @param token     the compact JWT string ("header.payload.signature")
     * @param secretKey the Base64‑encoded HMAC secret key
     * @return a {@link Jws} containing {@link Header} and {@link Claims}
     * @throws JwtException if parsing or signature validation fails (expired, tampered, etc.)
     */
    public static Jws<Claims> parseAndValidate(final String token, final String secretKey) {
        final byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(keyBytes))
                .build()
                .parseClaimsJws(token);
    }

    /**
     * Extracts only the {@link Claims} (the JWT body) after validating signature.
     *
     * @param token     the compact JWT string
     * @param secretKey the Base64‑encoded HMAC secret key
     * @return the JWT claims
     * @throws JwtException if token is invalid or signature check fails
     */
    public static Claims getClaims(final String token, final String secretKey) {
        return parseAndValidate(token, secretKey).getBody();
    }


    /**
     * Parses and verifies a JWT, returning its JwsHeader (which implements Map<String, Object>).
     *
     * @param token     the JWT string
     * @param secretKey the Base64‑encoded HMAC secret key
     * @return the JWT header (alg, typ, etc.)
     * @throws JwtException if token is invalid
     */
    public static JwsHeader<?> getHeader(final String token, final String secretKey) {
        return parseAndValidate(token, secretKey).getHeader();
    }

    /**
     * Returns the token's expiration instant, or null if no exp claim is set.
     *
     * @param token     the JWT string
     * @param secretKey the Base64‑encoded HMAC secret key
     * @return the {@link Instant} of expiration, or null if none
     * @throws JwtException if token is invalid
     */
    public static Instant getExpiration(final String token, final String secretKey) {
        final Date exp = getClaims(token, secretKey).getExpiration();
        return (exp != null ? exp.toInstant() : null);
    }

    /**
     * Convenience method to check if the token is expired at the current time.
     *
     * @param token     the JWT string
     * @param secretKey the Base64‑encoded HMAC secret key
     * @return true if now is after the token's exp claim, false otherwise
     * @throws JwtException if token is invalid
     */
    public static boolean isExpired(final String token, final String secretKey) {
        final Instant exp = getExpiration(token, secretKey);
        return (exp != null && Instant.now().isAfter(exp));
    }

    /**
     * Extracts the raw payload (body) JSON string without verifying the signature.
     * <strong>Do not use in production for security‑sensitive logic!</strong>
     *
     * @param token the JWT string
     * @return the Base64‑decoded payload JSON
     */
    public static String decodePayloadNoVerify(String token) {
        final String[] sections = token.split("\\.");

        if (sections.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format: " + token);
        }
        final String payload = sections[SecurityConstant.PAYLOAD_INDEX];
        final byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);

        return new String(decodedPayload, StandardCharsets.UTF_8);
    }

}
