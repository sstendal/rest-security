package sstendal.restsecurity;

/**
 * A parsed and verified claim from a JwtToken
 *
 * User: Sigurd Stendal
 * Date: 15.11.14
 */
public class JwtClaims {

    public static JwtClaims verified(String subject, String sessionId) {
        return new JwtClaims(State.VERIFIED, subject, sessionId);
    }

    public static JwtClaims notVerified() {
        return new JwtClaims(State.NOT_VERIFIED, null, null);
    }

    public enum State {VERIFIED, NOT_VERIFIED}

    private State state;
    private String subject;
    private String sessionId;

    private JwtClaims(State state, String subject, String sessionId) {
        this.state = state;
        this.subject = subject;
        this.sessionId = sessionId;
    }

    public State getState() {
        return state;
    }

    public String getSubject() {
        if(state == State.NOT_VERIFIED) throw new IllegalStateException("Claim is not verified");
        return subject;
    }

    public String getSessionId() {
        if(state == State.NOT_VERIFIED) throw new IllegalStateException("Claim is not verified");
        return sessionId;
    }

}
