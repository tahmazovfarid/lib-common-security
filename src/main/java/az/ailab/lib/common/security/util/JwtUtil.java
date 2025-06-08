package az.ailab.lib.common.security.util;

import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.security.constants.TokenField;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.List;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Utility methods for parsing, validating, and extracting data from JWTs
 * using the JJWT library.
 * <p>
 * All methods assume the token is signed with an HMAC secret (HS256+).
 * The secretKey parameter must be a Base64‑encoded string.
 * </p>
 */
public final class JwtUtil {

    private JwtUtil() {
        /* utility class */
    }

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
    public static Claims getPayload(final String token, final String secretKey) {
        return parseAndValidate(token, secretKey).getBody();
    }

    /**
     * Parses and verifies a JWT, returning its JwsHeader.
     *
     * @param claimsJws the claims from jws
     * @return the JWT header (alg, typ, etc.)
     * @throws JwtException if token is invalid
     */
    public static JwsHeader<?> getHeader(Jws<Claims> claimsJws) {
        return claimsJws.getHeader();
    }

    /**
     * Extracts the subject (typically the username or user identifier) from the given JWT claims.
     *
     * @param payload the JWT claims object containing the token payload
     * @return the subject (e.g., user identifier) embedded in the token
     * @throws NullPointerException if the subject field is missing in the claims
     */
    public static String extractSubject(Claims payload) {
        return payload.getSubject();
    }

    /**
     * Extracts granted authorities (roles and permissions) from the given JWT claims.
     * <p>
     * It reads the user role and permission structure from the claims,
     * and converts them into a list of {@link GrantedAuthority} instances, including:
     * <ul>
     *     <li>A single role (prefixed with {@code ROLE_})</li>
     *     <li>Multiple permission keys (as-is, no prefix)</li>
     * </ul>
     *
     * Example JSON structure expected in claims:
     * <pre>
     * {
     *   "user": {
     *     "role": {
     *       "type": "ADMIN",
     *       "permissions": {
     *         "USER_READ": "INSTITUTION",
     *         "USER_EDIT": "INSTITUTION"
     *       }
     *     }
     *   }
     * }
     * </pre>
     *
     * @param payload the JWT claims payload to extract data from
     * @param objectMapper Jackson ObjectMapper used to convert claims to a tree structure
     * @return a list of {@link GrantedAuthority} including the user's role and permission keys
     * @throws IllegalStateException if extraction fails due to malformed claims
     */
    public List<GrantedAuthority> extractAuthorities(final Claims payload, final ObjectMapper objectMapper) {
        try {
            JsonNode root = objectMapper.valueToTree(payload);
            JsonNode roleNode = root.path(TokenField.USER).path(TokenField.ROLE);

            String roleType = roleNode.path(TokenField.TYPE).asText();
            JsonNode permissionsNode = roleNode.path(TokenField.PERMISSIONS);

            Stream<GrantedAuthority> roleStream = Stream.of(
                    new SimpleGrantedAuthority(SecurityConstant.ROLE_PREFIX + roleType)
            );

            Stream<GrantedAuthority> permissionStream = StreamSupport
                    .stream(Spliterators.spliteratorUnknownSize(
                            permissionsNode.fieldNames(), Spliterator.ORDERED), false)
                    .map(SimpleGrantedAuthority::new);

            return Stream.concat(roleStream, permissionStream)
                    .collect(Collectors.toList());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract permissions from JWT", e);
        }
    }

    /**
     * Returns the token's expiration instant, or null if no exp claim is set.
     *
     * @param payload – the JWT payload
     * @return the {@link Instant} of expiration, or null if none
     * @throws JwtException if token is invalid
     */
    public static Instant extractExpiration(Claims payload) {
        final Date exp = payload.getExpiration();
        return (exp != null ? exp.toInstant() : null);
    }

    /**
     * Convenience method to check if the token is expired at the current time.
     *
     * @param payload     the JWT payload
     * @return true if now is after the token's exp claim, false otherwise
     * @throws JwtException if token is invalid
     */
    public static boolean isExpired(Claims payload) {
        final Instant exp = extractExpiration(payload);
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
