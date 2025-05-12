package az.ailab.lib.common.security.util;

import az.ailab.lib.common.security.constants.SecurityConstant;
import az.ailab.lib.common.util.HeaderUtil;
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