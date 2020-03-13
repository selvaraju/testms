package pl.piomin.microservices.auth.dao;

public interface UserDoaService {
    public User authenticate(String username, String pwd) throws Exception;
}
