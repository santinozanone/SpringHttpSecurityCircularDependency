package root;

import jakarta.servlet.FilterRegistration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import root.authentication.providers.OtpAuthenticationProvider;
import root.authentication.providers.UsernamePasswordAuthenticationProvider;
import root.filters.InitialAuthenticationFilter;
import root.filters.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {

	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;

	@Autowired
	private InitialAuthenticationFilter initialAuthenticationFilter;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		return http.csrf().disable().httpBasic().and()
				.addFilterBefore(initialAuthenticationFilter, BasicAuthenticationFilter.class)
				.addFilterAfter(jwtAuthenticationFilter, BasicAuthenticationFilter.class).authorizeHttpRequests()
				.requestMatchers("/actuator/**").permitAll().
				and().authorizeHttpRequests().anyRequest().authenticated()
				.and().build();
	}




	@Bean
	public UserDetailsService userDetailsService(){
		UserDetails user = User.builder()
				.username("user")
				.password("123")
				.roles("USER")
				.build();
		UserDetails admin = User.builder()
				.username("admin")
				.password("123")
				.roles("USER", "ADMIN")
				.build();
		return new InMemoryUserDetailsManager(user, admin);

	}

	
	@Bean
	public ServletContextInitializer servletContextInitializer() {
		return servletContext -> {
			// Get all filter registrations
			for (FilterRegistration registration : servletContext.getFilterRegistrations().values()) {
				System.out.println("filter" + registration.getName());
			}
		};
	}

	@Bean
	public FilterRegistrationBean JwtFilterRegistration(JwtAuthenticationFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean(filter);
		registration.setEnabled(false);
		return registration;
	}

	@Bean
	public FilterRegistrationBean InitialAuthenticationFilterRegistration(InitialAuthenticationFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean(filter);
		registration.setEnabled(false);
		return registration;
	}

}
