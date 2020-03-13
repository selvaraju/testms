package pl.piomin.microservices.account.api;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import pl.piomin.microservices.account.model.Account;

@RestController
public class Api {

	
	protected Logger logger = Logger.getLogger(Api.class.getName());
	
	public Api() {
	}
	
	@RequestMapping("/auth/")
	public Account findByNumber(@PathVariable("number") String number) {
		logger.info(String.format("Account.findByNumber(%s)", number));
		return "Hi";
	}
	
	
}
