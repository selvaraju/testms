package pl.piomin.microservices.auth.api;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
@RestController
public class Api {


	@Autowired
	private AuthenticationManager authenticationManager;
	protected Logger logger = Logger.getLogger(Api.class.getName());
	
	public Api() {
	}
	
	@RequestMapping("/auth/{number}")
	public String findByNumber(@PathVariable("number") String number) {
		logger.info(String.format("Account.findByNumber(%s)", number));
		return "Hi";


	}

	private void authenticate(String username, String password) throws Exception {
		try {
            LoginAuthProvider pl = new LoginAuthProvider();
			pl.
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}
