package sstendal.restsecurity;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * User: Sigurd Stendal
 * Date: 15.11.14
 */
public class AuthorizationHeaderTest {

    @Test
    public void can_parse_basic() {

        AuthorizationHeader h = AuthorizationHeader.parse("Basic bXlfdXNlcm5hbWU6YVNlQ3JFdA==");

        assertEquals("my_username", h.getUsername());
        assertEquals("aSeCrEt", h.getPassword());
        assertNull(h.getToken());

    }

    @Test
    public void can_parse_bearer() {

        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBbiBJc3N1ZXIiLCJzdWIiOiJteV91c2VybmFtZSIsImlhdCI6MTQxNjA1MzY5OCwic2Vzc2lvbiI6InNlc3Npb24tMTIzIn0.t4_eslmS3rIJWJIjPhvhUOlAXQgi-_HuLnarUnyk_i8";
        AuthorizationHeader h = AuthorizationHeader.parse("Bearer " + jwt);

        assertEquals(jwt, h.getToken());
        assertNull(h.getUsername());
        assertNull(h.getPassword());

    }

}
