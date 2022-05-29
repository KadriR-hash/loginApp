package tn.enicarthage.springboot;

import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final UserDetailsService userDetailsService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);	
	}

@Override
protected void configure(HttpSecurity http) throws Exception {
	//JWT
	
	//disable cross site request forgery
	http.csrf().disable();
	//Spring Security will never create an HttpSession and it will never use it to obtain the SecurityContext
	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	//permit all to access this application
	http.authorizeRequests().anyRequest().permitAll();
	http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
	
}


@Bean
@Override
//AuthenticationManager exists in WebSecurityConfigurerAdapter
public AuthenticationManager authenticationManagerBean() throws Exception {
	return super.authenticationManagerBean();
}
	
	
}
