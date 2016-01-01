package demo.filter;

import demo.security.AppUserDetails;
import demo.security.AuthoritiesConstants;
import demo.security.SecurityUtils;
import demo.security.jwt.TokenAuthenticationService;
import demo.security.jwt.UserAuthentication;
import demo.security.jwt.UserService;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

public class TokenGeneratorFilter extends OncePerRequestFilter {

    private TokenAuthenticationService tokenAuthenticationService;
    private UserService userService;

    public TokenGeneratorFilter(TokenAuthenticationService tokenAuthenticationService, UserService userService) {
        this.tokenAuthenticationService = tokenAuthenticationService;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // If the user has been authenticated with CAS, add the OAuth2 bearer token
        if (SecurityUtils.isAuthenticated()) {
            // Spring put the X-AUTH-TOKEN token in header
            String authHeader = request.getHeader("X-AUTH-TOKEN");
            if (authHeader == null) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = ((AppUserDetails)authentication.getPrincipal()).getUserid();
                String pwd = authentication.getCredentials().toString(); // This is the CAS ticket
                establishUserAndLogin(response, email, new BCryptPasswordEncoder().encode(pwd)); // encrypt the CAS ticket
            }
        }
        filterChain.doFilter(request, response);
    }

    private String establishUserAndLogin(HttpServletResponse response, String email, String pwd) {

        // Find user, create if necessary
        org.springframework.security.core.userdetails.User user;
        try {
            user = userService.loadUserByUsername(email);
        } catch (UsernameNotFoundException e) {
            // TODO: add granted authorities from CAS SAML assertion
            user = new org.springframework.security.core.userdetails.User(email, pwd, AuthorityUtils.createAuthorityList(AuthoritiesConstants.ADMIN));
            userService.addUser(user);
        }

        // Login that user
        UserAuthentication authentication = new UserAuthentication(user);
        return tokenAuthenticationService.addAuthentication(response, authentication);
    }
}
