package pl.piomin.microservices.auth.login;

import org.springframework.security.authentication.AuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pl.piomin.microservices.auth.user.ARUser;
import pl.piomin.microservices.auth.user.LocalUserService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.security.core.userdetails.User;

public class LoginAuthProvider implements AuthenticationProvider {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private LocalUserService localUserService;

    public LoginAuthProvider(LocalUserService localUserService) {
        this.localUserService = localUserService;
    }

    /**
     * Performs authentication.
     *
     * @param auth UsernamePasswordAuthenticationToken.
     * @return authenticated object.
     * @throws AuthenticationException if authentication fails.
     */
    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        Assert.notNull(auth, "No authentication data provided.");
        String userName = (String) auth.getPrincipal();
        String password = (String) auth.getCredentials();


        ARUser user = null;
        try {
            user = localUserService.authenticate(userName, password);
        } catch (Exception ex) {
            log.debug(" Authentication failed for user: " + userName, ex);
        }

        if (user == null) {
            throw new BadCredentialsException("Invalid Username/Password.");
        }

        // Check for user privileges.
        if (user.getAuthorities().isEmpty()) {
            throw new InsufficientAuthenticationException(
                    user.getUsername() + " user has no roles assigned.");
        }

        return new LoginAuthToken(user, null, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginAuthToken.class.isAssignableFrom(authentication);
    }


    private ARUser geARUser(User principal) {
        log.debug("Found user details in authentication. Creating OneOps User.");
        String userName = principal.getUsername();
        String password = principal.getPassword();

        if (password == null) {
            log.debug(userName + " credentials are already erased.");
            password = "";
        }
        return new ARUser(
                userName, password, principal.getAuthorities(), userName);
    }

}
