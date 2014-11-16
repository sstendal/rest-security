package sstendal.restsecurity;

import java.security.Principal;
import java.util.List;

/**
 * User: Sigurd Stendal
 * Date: 27.02.14
 */
public class UserPrincipal implements Principal {

    private String username;
    private String sessionToken;
    private List<String> roles;

    public UserPrincipal(String username, String sessionToken, List<String> roles) {
        this.username = username;
        this.sessionToken = sessionToken;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }

    public List<String> getRoles() {
        return roles;
    }

    public boolean isInRole(String role) {
        return roles.contains(role);
    }

    @Override
    public String getName() {
        return username;
    }
}
