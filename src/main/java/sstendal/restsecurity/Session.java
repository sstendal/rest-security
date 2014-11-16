package sstendal.restsecurity;

import java.util.List;

/**
 * User: Sigurd Stendal
 * Date: 15.11.14
 */
public class Session {

    private enum State {VALID, NOT_VALID}

    public static Session createValid(String id, String username, List<String> roles) {
        return new Session(id, username, roles, State.VALID);
    }

    public static Session createNotValid() {
        return new Session(null, null, null, State.NOT_VALID);
    }

    private String id;
    private String username;
    private List<String> roles;
    private State state;

    private Session(String id, String username, List<String> roles, State state) {
        this.id = id;
        this.username = username;
        this.roles = roles;
        this.state = state;
    }

    public String getId() {
        if(state == State.NOT_VALID) throw new IllegalStateException("Session is not valid");
        return id;
    }

    public String getUsername() {
        if(state == State.NOT_VALID) throw new IllegalStateException("Session is not valid");
        return username;
    }

    public List<String> getRoles() {
        if(state == State.NOT_VALID) throw new IllegalStateException("Session is not valid");
        return roles;
    }

    public boolean isValid() {
        return state == State.VALID;
    }
}
