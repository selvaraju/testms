package pl.piomin.microservices.auth.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthToken  extends UsernamePasswordAuthenticationToken {

    public JwtAuthToken( Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
