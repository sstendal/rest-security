package sstendal.restsecurity;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.mockito.ArgumentCaptor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

import static org.mockito.Mockito.*;

/**
 * User: Sigurd Stendal
 * Date: 15.11.14
 */
public class RestLoginFilterTest {


    private static final String JWT_ISSUER = "The Issuer";
    private static final String BASIC_AUTH_DOMAIN = "A Security Domain";

    private FilterChain filterChain;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private LoginService loginService;

    @Before
    public void before() {
        filterChain = mock(FilterChain.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        loginService = mock(LoginService.class);
    }

    @Test
    public void works_without_login_header() throws IOException, ServletException {

        createRestLoginFilter().doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void basic_auth() throws IOException, ServletException {

        when(request.getHeader("Authorization")).thenReturn("Basic bXlfdXNlcm5hbWU6YVNlQ3JFdA==");
        when(loginService.login("my_username", "aSeCrEt")).thenReturn(Session.createValid("session-123", "my_username", Arrays.asList("admin")));

        createRestLoginFilter().doFilter(request, response, filterChain);

        ArgumentCaptor<HttpServletRequest> captor = ArgumentCaptor.forClass(HttpServletRequest.class);
        verify(filterChain).doFilter(captor.capture(), any());
        assertEquals("my_username", captor.getValue().getUserPrincipal().getName());
        assertTrue(captor.getValue().isUserInRole("admin"));
        assertFalse(captor.getValue().isUserInRole("something else"));
    }

    @Test
    public void basic_auth_wrong_pwd() throws IOException, ServletException {

        when(request.getHeader("Authorization")).thenReturn("Basic bXlfdXNlcm5hbWU6YVNlQ3JFdA==");
        when(loginService.login("my_username", "aSeCrEt")).thenReturn(Session.createNotValid());

        createRestLoginFilter().doFilter(request, response, filterChain);

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verifyZeroInteractions(filterChain);
    }

    @Test
    public void jwt_auth() throws IOException, ServletException {

        JwtToken jwtToken = new JwtToken(JWT_ISSUER);
        String jwt = jwtToken.generate("my_username", "session-123");

        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);
        when(loginService.getSession("session-123")).thenReturn(Session.createValid("session-123", "my_username", Arrays.asList("admin")));

        createRestLoginFilter().doFilter(request, response, filterChain);

        ArgumentCaptor<HttpServletRequest> httpServletRequest = ArgumentCaptor.forClass(HttpServletRequest.class);
        verify(filterChain).doFilter(httpServletRequest.capture(), any());
        assertEquals("my_username", httpServletRequest.getValue().getUserPrincipal().getName());
        assertTrue(httpServletRequest.getValue().isUserInRole("admin"));
        assertFalse(httpServletRequest.getValue().isUserInRole("something else"));
    }

    @Test
    public void jwt_auth_with_invalid_sessionid() throws IOException, ServletException {

        JwtToken jwtToken = new JwtToken(JWT_ISSUER);
        String jwt = jwtToken.generate("my_username", "invalid-session-id");

        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt);
        when(loginService.getSession("invalid-session-id")).thenReturn(Session.createNotValid());

        createRestLoginFilter().doFilter(request, response, filterChain);

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verifyZeroInteractions(filterChain);
    }

    @Test
    public void forged_jwt_auth() throws IOException, ServletException {

        JwtToken jwtToken = new JwtToken(JWT_ISSUER);
        String jwt = jwtToken.generate("my_username", "false-session-id");

        when(request.getHeader("Authorization")).thenReturn("Bearer " + jwt + "extra-chars");
        when(loginService.getSession("false-session-id")).thenReturn(Session.createNotValid());

        createRestLoginFilter().doFilter(request, response, filterChain);

        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verifyZeroInteractions(filterChain);
    }

    private RestLoginFilter createRestLoginFilter() {
        return new RestLoginFilter() {

            @Override
            protected String getJwtIssuer() {
                return JWT_ISSUER;
            }

            @Override
            protected String getBasicAuthDomain() {
                return BASIC_AUTH_DOMAIN;
            }

            @Override
            protected LoginService getLoginService() {
                return loginService;
            }
        };
    }



}
