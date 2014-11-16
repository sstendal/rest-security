package sstendal.restsecurity;

import javax.servlet.http.HttpSession;

/**
 * User: Sigurd Stendal
 * Date: 15.11.14
 */
public interface LoginService {

    Session login(String username, String password);

    Session getSession(String sessionId);

    Session getCookieSession(HttpSession session);

}
