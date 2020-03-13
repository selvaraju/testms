package pl.piomin.microservices.auth.user;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class ARUser extends User{

    private final String license;

    public ARUser(User user){
        this(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities(),
                user.getUsername());

    }

    public ARUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String license) {
        super(username, password, authorities);
        this.license = license;
    }

    public String getLicense() { return license; }

    public boolean hasRole(Role role) {
        return getAuthorities()
                .stream()
                .anyMatch(a -> a.getAuthority().equalsIgnoreCase(role.authority()));
    }
    public enum Role {
        USER,
        ADMIN,
        MGMT;

        public String authority() { return "ROLE_" + name();}
    }
}
