package sstendal.restsecurity;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * User: Sigurd Stendal
 * Date: 15.11.14
 */
public class JwtTokenTest {

    @Test
    public void can_generate_and_verify() {

        String issuer = "An Issuer";
        JwtToken jwtToken = new JwtToken(issuer);


        String jwt = jwtToken.generate("my_username", "session-123");
        assertNotNull(jwt);

        JwtClaims claims = jwtToken.verifyAndGetClaims(jwt);

        assertEquals("my_username", claims.getSubject());
        assertEquals("session-123", claims.getSessionId());

    }

}
