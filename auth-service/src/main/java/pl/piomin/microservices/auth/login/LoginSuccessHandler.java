package pl.piomin.microservices.auth.login;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import pl.piomin.microservices.auth.token.JwtTokenService;

public abstract class LoginSuccessHandler {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final ObjectMapper mapper;
    private final JwtTokenService tokenService;

    public LoginSuccessHandler(ObjectMapper mapper, JwtTokenService tokenService) {
        this.mapper = mapper;
        this.tokenService = tokenService;

    }
}
