package root.filters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import root.authentication.OtpAuthentication;
import root.authentication.UsernamePasswordAuthentication;


@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private AuthenticationManager manager;

	@Value("${jwt.signing.key}")
	private String signingKey;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String username = request.getHeader("username");
		String password = request.getHeader("password");
		String code = request.getHeader("code");
		if (code == null) {
			Authentication a = new UsernamePasswordAuthentication(username, password);
			manager.authenticate(a);
		} else {
			Authentication a = new OtpAuthentication(username, code);
			a = manager.authenticate(a);
			SecretKey key = Keys.hmacShaKeyFor(signingKey.getBytes(StandardCharsets.UTF_8));
			
			String jwt = Jwts.builder()
					.setClaims(Map.of("username", username))
					.signWith(key)
					.compact();
		
			response.setHeader("Authorization", jwt);
		}
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return request.getServletPath().equals("/login");
	}

}
