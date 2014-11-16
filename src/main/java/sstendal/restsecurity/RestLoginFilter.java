package sstendal.restsecurity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.List;

/**
 * Base class for a REST login filter.
 * <p/>
 * User: Sigurd Stendal
 * Date: 08.02.14
 */
public abstract class RestLoginFilter implements Filter {

    protected Logger logger = LoggerFactory.getLogger(RestLoginFilter.class);

    private LoginService loginService;

    private JwtToken jwtToken;

    /**
     * Issuer string to use in JWT token.
     */
    protected abstract String getJwtIssuer();

    /**
     * Domain to return in Basic authentication challenge.
     * <p/>
     * Set to null to avoid sending a challenge.
     * <p/>
     * NB! A challenge will trigger the browsers native login dialog, which may not be what you want.
     */
    protected abstract String getBasicAuthDomain();

    /**
     * Backend login service implementation.
     */
    protected abstract LoginService getLoginService();

    public RestLoginFilter() {
        jwtToken = new JwtToken(getJwtIssuer());
        loginService = getLoginService();
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {


        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String header = request.getHeader("Authorization");

        AuthorizationHeader data = AuthorizationHeader.parse(header);

        Session session = Session.createNotValid();
        switch (data.getType()) {
            case BASIC:
                logger.debug("Verifies username and password from basic authentication header");
                session = loginService.login(data.getUsername(), data.getPassword());
                if (!session.isValid()) {
                    logger.error("Login failed");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    String basicAuthDomain = getBasicAuthDomain();
                    if (basicAuthDomain != null) {
                        response.setHeader("WWW-Authenticate", "Basic realm=" + basicAuthDomain);
                    }
                    return;
                }
                break;
            case TOKEN:
                logger.debug("Verifies JWT token");
                JwtClaims claims = jwtToken.verifyAndGetClaims(data.getToken());
                if (claims.getState() != JwtClaims.State.VERIFIED) {
                    logger.error("JWT token does not verify: " + claims.getState());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }

                session = loginService.getSession(claims.getSessionId());
                if (!session.isValid()) {
                    logger.error("Invalid session id found in JWT token: " + claims.getSessionId());
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
                if (!nullSafeEquals(session.getUsername(), claims.getSubject())) {
                    throw new IllegalStateException("JWT claim found, but username in JWT claim does not match username in session. JWT Claim username: '" + claims.getSubject() + "'. Session username: '" + session.getUsername() + "'");
                }
                break;

            case NOT_FOUND:
                // No login data in headers. Looking for user session in http session
                if (request.getSession(false) != null) {
                    logger.debug("Verifies authentication in http session");
                    session = loginService.getCookieSession(request.getSession(false));
                    if (session.isValid()) {
                        logger.info("Found existing user session authenticated by cookie");
                    }
                }
                break;

            case UNABLE_TO_PARSE:
            case UNKNOWN_TYPE:
                break;

            default:
                throw new IllegalStateException("Unknown type: " + data.getType());
        }

        if (session.isValid()) {
            logger.info("Request was successfully authenticated");
            request = wrappedHttpServletRequest(request, session.getRoles(), session.getUsername(), session.getId());
        }

        filterChain.doFilter(request, response);

    }

    @Override
    public void destroy() {

    }


    private HttpServletRequest wrappedHttpServletRequest(HttpServletRequest request, List<String> roles, String username, String sessionId) {

        final UserPrincipal userPrincipal = new UserPrincipal(username, sessionId, roles);

        return new HttpServletRequestWrapper(request) {
            @Override
            public Principal getUserPrincipal() {
                return userPrincipal;
            }

            @Override
            public String getAuthType() {
                return HttpServletRequest.BASIC_AUTH;
            }

            @Override
            public String getRemoteUser() {
                return userPrincipal.getName();
            }

            @Override
            public boolean isUserInRole(String role) {
                return userPrincipal.isInRole(role);
            }

        };
    }

    private boolean nullSafeEquals(String a, String b) {
        return (a == null && b == null) || (a != null && a.equals(b));
    }

}
