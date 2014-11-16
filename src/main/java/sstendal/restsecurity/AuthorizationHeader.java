package sstendal.restsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;

/**
 * Authorization header in an HTTP request. Handles both basic authentication and json web tokens.
 * <p>
 * User: Sigurd Stendal
 * Date: 11.10.12
 */
public class AuthorizationHeader {

    protected static Logger logger = LoggerFactory.getLogger(AuthorizationHeader.class);

    public static AuthorizationHeader parse(String header) {

        if (header == null) {
            logger.debug("Authorization header field is empty");
            return new AuthorizationHeader(Type.NOT_FOUND);
        }
        if (header.startsWith("Basic ")) {
            logger.debug("Authorization header field contains a basic authentication token");
            return parseBasic(header);
        }
        if (header.startsWith("Bearer ")) {
            logger.debug("Authorization header field contains a JWT authentication token");
            return parseJwt(header);
        }

        logger.warn("Authorization header field contains an unknown authorization token: " + header);
        return new AuthorizationHeader(Type.UNKNOWN_TYPE);
    }

    private static AuthorizationHeader parseBasic(String header) {
        if (header.length() == "Basic ".length()) {
            logger.error("Failed while parsing Authorization header field. Authorization header was only 'Basic '. Username and password was missing.");
            return new AuthorizationHeader(Type.UNABLE_TO_PARSE);
        }
        String authorization = new String(Base64.getDecoder().decode(header.substring("Basic ".length())));
        int i = authorization.indexOf(":");
        if (i == -1) {
            logger.error("Failed while parsing Authorization header field. Base64 encoded data did not contain any ':'");
            return new AuthorizationHeader(Type.UNABLE_TO_PARSE);
        }
        AuthorizationHeader data = new AuthorizationHeader(AuthorizationHeader.Type.BASIC);
        data.username = authorization.substring(0, i);
        data.password = authorization.substring(data.username.length() + 1);
        return data;
    }

    private static AuthorizationHeader parseJwt(String header) {
        if (header.length() == "Bearer ".length()) {
            logger.error("Failed while parsing Authorization header field. Authorization header was only 'Bearer '. Token was missing.");
            return new AuthorizationHeader(Type.UNABLE_TO_PARSE);
        }
        AuthorizationHeader data = new AuthorizationHeader(AuthorizationHeader.Type.TOKEN);
        data.token = header.substring("Bearer ".length());
        return data;
    }

    public enum Type {BASIC, TOKEN, NOT_FOUND, UNKNOWN_TYPE, UNABLE_TO_PARSE}

    public AuthorizationHeader(Type type) {
        this.type = type;
    }

    private Type type;
    private String username;
    private String password;
    private String token;

    public Type getType() {
        return type;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getToken() {
        return token;
    }
}


