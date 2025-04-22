package az.ailab.lib.common.security.util;

import az.ailab.lib.common.error.ServiceException;
import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.util.HeaderUtil;
import jakarta.validation.constraints.NotNull;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.springframework.http.HttpHeaders;

/**
 * Utility class for extracting security-related information from HTTP headers.
 *
 * <p>This class provides static methods to retrieve authorization tokens,
 * service names, and API keys from request headers. It is designed to simplify
 * access to common security-related header information.</p>
 *
 * <p>The class cannot be instantiated, as all methods are static utility methods.</p>
 *
 * @since 1.0
 */
public final class SecurityUtil {

    /**
     * Private constructor to prevent instantiation of the utility class.
     * Ensures that the class can only contain static methods and cannot be initialized.
     */
    private SecurityUtil() {
        // Utility class, no instantiation
    }

    /**
     * Extracts the access token from the Authorization header.
     *
     * <p>This method looks for a Bearer token in the Authorization header.
     * If found, it returns the token without the "Bearer " prefix.
     * If no valid token is found, it returns null.</p>
     *
     * @return The access token as a string, or null if no token is present
     */
    public static String getAccessToken() {
        return getAuthorizationHeaderOpt()
                .filter(header -> header.startsWith(SecurityConstant.BEARER))
                .map(header -> header.substring(SecurityConstant.BEARER.length()))
                .orElse(null);
    }

    /**
     * Extracts the payload segment from a JWT and returns it as a decoded UTF‑8 JSON string.
     * <p>
     * Splits the token on “.”, verifies it has exactly three parts (header, payload, signature),
     * Base64‑URL decodes the payload section, and converts it to a UTF‑8 string.
     * </p>
     *
     * @param token the JWT string in the form "header.payload.signature"; must not be null or empty
     * @return the decoded payload JSON as a UTF‑8 string
     * @throws IllegalArgumentException if the token does not consist of three segments or the payload cannot be decoded
     */
    public static String extractPayload(@NotNull final String token) {
        final String[] sections = token.split("\\.");

        if (sections.length == 3) {
            final String payload = sections[SecurityConstant.PAYLOAD_INDEX];
            final byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);
            return new String(decodedPayload, StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException("Invalid token: " + token);
        }
    }

    /**
     * Retrieves the full Authorization header value.
     *
     * <p>Returns the complete Authorization header if present,
     * or null if the header is not found.</p>
     *
     * @return The full Authorization header as a string, or null
     */
    public static String getAuthorizationHeader() {
        return getAuthorizationHeaderOpt().orElse(null);
    }

    /**
     * Provides an optional containing the Authorization header.
     *
     * <p>This method allows for safe retrieval of the Authorization header,
     * returning an empty Optional if the header is not present.</p>
     *
     * @return An Optional containing the Authorization header
     */
    public static Optional<String> getAuthorizationHeaderOpt() {
        return HeaderUtil.getOpt(HttpHeaders.AUTHORIZATION);
    }

    /**
     * Retrieves the service name from the X-Service-Name header.
     *
     * <p>Returns the service name if present in the header,
     * or null if the header is not found.</p>
     *
     * @return The service name as a string, or null
     */
    public static String getXServiceName() {
        return HeaderUtil.getOpt(SecurityConstant.X_SERVICE_NAME).orElse(null);
    }

    /**
     * Retrieves the service API key from the X-Client-Api-Key header.
     *
     * <p>Returns the service API key if present in the header,
     * or null if the header is not found.</p>
     *
     * @return The service API key as a string, or null
     */
    public static String getXServiceApiKey() {
        return HeaderUtil.getOpt(SecurityConstant.X_Client_API_KEY).orElse(null);
    }

}