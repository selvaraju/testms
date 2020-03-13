package pl.piomin.microservices.auth.dao;

import pl.piomin.microservices.auth.user.ARUser;

public class UserDoaServiceImpl implements UserDoaService {

    // We will call this directly to DB. since this is the entry point
    @Override
    public User authenticate(String username, String pwd) {

        if("selva".equalsIgnoreCase(username) && "selva".equalsIgnoreCase(pwd)) {
            User user = new User() ;
            user.setUserName("selva");
            user.setFirstName("selva");
            user.setLatsName("raju");
            user.setEmail("selva@gmail.cpm");
            user.setRole(ARUser.Role.USER);
            user.setLicense("CHQ853");
            return user;
        }else {
            // need proper exception procedure
            throw new RuntimeException("Login failed!");
        }

    }
}
