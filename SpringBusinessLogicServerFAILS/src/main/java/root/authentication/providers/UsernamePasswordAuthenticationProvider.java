package root.authentication.providers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import root.authentication.UsernamePasswordAuthentication;
import root.services.AuthenticationServerProxy;

@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider{
	 
	@Autowired
	private AuthenticationServerProxy proxy;
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		 String password = String.valueOf(authentication.getCredentials());
		 proxy.sendAuth(username, password);
		 return new UsernamePasswordAuthenticationToken(username, password);
		
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return UsernamePasswordAuthentication.class.isAssignableFrom(authentication);
	}

}
