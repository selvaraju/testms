package pl.piomin.microservices.auth.user;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import pl.piomin.microservices.auth.dao.User;
import pl.piomin.microservices.auth.dao.UserDoaService;
import pl.piomin.microservices.auth.dao.UserDoaServiceImpl;
import zipkin.internal.Nullable;

import java.util.Collections;

@Service
public class LocalUserService {

    private UserDoaService userDoaService;

    public LocalUserService() {
        userDoaService = new UserDoaServiceImpl();
    }

    public @Nullable ARUser authenticate(String username , String password) {

        User user = userDoaService.authenticate(username,password);
        return  new ARUser(
                username,
                password,
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole().authority())),
                user.getLicense()
        );

    }
}
