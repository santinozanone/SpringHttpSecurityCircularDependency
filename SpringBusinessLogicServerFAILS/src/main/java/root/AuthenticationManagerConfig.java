package root;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import root.authentication.providers.OtpAuthenticationProvider;
import root.authentication.providers.UsernamePasswordAuthenticationProvider;

@Configuration
//@DependsOn({"securityFilterChain"})
public class AuthenticationManagerConfig {


    @Autowired
    private OtpAuthenticationProvider otpAuthenticationProvider;
    @Autowired
    private UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;


    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
       AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(usernamePasswordAuthenticationProvider).authenticationProvider(otpAuthenticationProvider);

        return authenticationManagerBuilder.build();
    }
   

}
