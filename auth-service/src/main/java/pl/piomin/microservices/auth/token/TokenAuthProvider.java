package pl.piomin.microservices.auth.token;


import io.jsonwebtoken.*;
import org.slf4j.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;

import pl.piomin.microservices.auth.user.ARUser;

public class TokenAuthProvider implements AuthenticationProvider {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final JwtTokenService jwtTokenService;

    public TokenAuthProvider(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("Validating and authenticating the token.");
        JwtAuthToken authToken = (JwtAuthToken) authentication;
        String jwtToken = (String) authToken.getCredentials();
        authToken.eraseCredentials(); // Now we can erase the credentials.
        ARUser user;
        try {
            user = jwtTokenService.createUser(jwtToken);
        } catch (ExpiredJwtException ex) {
            throw new CredentialsExpiredException("Token has expired.", ex);
        } catch (JwtException ex) {
            throw new BadCredentialsException("Invalid Authorization Token.", ex);
        }
        // Check for authorize claims.
        if (user.getAuthorities().isEmpty()) {
            throw new InsufficientAuthenticationException(
                    user.getUsername() + " user has no roles assigned.");
        }
        return new JwtAuthToken(user, null, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthToken.class.isAssignableFrom(authentication);
    }
}