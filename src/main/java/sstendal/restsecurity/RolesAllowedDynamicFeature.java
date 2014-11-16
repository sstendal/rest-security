package sstendal.restsecurity;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.lang.reflect.Method;

/**
 * Copy of RolesAllowedDynamicFeature from Jersey.
 * <p/>
 * Added feature: Responds with 401 if the user was not logged in at all and the resource requires authentication.
 * <p/>
 * Set the configuration property "restsecurity.challenge" to create a challenge header.
 * <p/>
 * I.e. set it to "Basic realm=My domain" to create a challenge header for basic authentication.
 * NB! This will trigger the browsers native user dialog for login, which may not be what you want.
 * <p/>
 * Usage example:
 * <pre>
 *      public class MyApplication extends ResourceConfig {
 *
 *            public MyApplication() {
 *               super();
 *               register(RolesAllowedDynamicFeature.class);
 *               HashMap<String, Object> p = new HashMap<>();
 *                p.put("restsecurity.challenge", "Basic realm=My domain");
 *               addProperties(p);
 *            }
 *       }
 * </pre>
 * <p/>
 * User: Sigurd Stendal
 * Date: 28.02.14
 */
public class RolesAllowedDynamicFeature implements DynamicFeature {

    private static final String CHALLENGE_CONFIG_KEY = "restsecurity.challenge";

    @Override
    public void configure(final ResourceInfo resourceInfo, final FeatureContext configuration) {
        Method am = resourceInfo.getResourceMethod();

        String challenge = (String) configuration.getConfiguration().getProperty(CHALLENGE_CONFIG_KEY);

        // DenyAll on the method take precedence over RolesAllowed and PermitAll
        if (am.isAnnotationPresent(DenyAll.class)) {
            configuration.register(new RolesAllowedRequestFilter());
            return;
        }

        // RolesAllowed on the method takes precedence over PermitAll
        RolesAllowed ra = am.getAnnotation(RolesAllowed.class);
        if (ra != null) {
            configuration.register(new RolesAllowedRequestFilter(ra.value(), challenge));
            return;
        }

        // PermitAll takes precedence over RolesAllowed on the class
        if (am.isAnnotationPresent(PermitAll.class)) {
            // Do nothing.
            return;
        }

        // DenyAll can't be attached to classes

        // RolesAllowed on the class takes precedence over PermitAll
        ra = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class);
        if (ra != null) {
            configuration.register(new RolesAllowedRequestFilter(ra.value(), challenge));
        }
    }

    @Priority(Priorities.AUTHORIZATION) // authorization filter - should go after any authentication filters
    private static class RolesAllowedRequestFilter implements ContainerRequestFilter {
        private final boolean denyAll;
        private final String[] rolesAllowed;
        private final String challenge;

        RolesAllowedRequestFilter() {
            this.denyAll = true;
            this.rolesAllowed = null;
            this.challenge = null;
        }

        RolesAllowedRequestFilter(String[] rolesAllowed, String challenge) {
            this.denyAll = false;
            this.rolesAllowed = (rolesAllowed != null) ? rolesAllowed : new String[]{};
            this.challenge = challenge;
        }

        @Override
        public void filter(ContainerRequestContext requestContext) throws IOException {
            if (!denyAll) {
                for (String role : rolesAllowed) {
                    if (requestContext.getSecurityContext().isUserInRole(role)) {
                        return;
                    }
                }

                // If the user simply was not authorized at all
                if (requestContext.getSecurityContext().getUserPrincipal() == null) {
                    if (challenge != null) {
                        throw new NotAuthorizedException(challenge);
                    } else {

                        throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED));
                    }
                }
            }

            throw new ForbiddenException();
        }
    }
}