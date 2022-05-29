package tn.enicarthage.springboot;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.extern.slf4j.Slf4j;
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authenticationManager;
	
	public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
		
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) 
			throws AuthenticationException {
		
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		log.info("user name is {}",username);
		log.info("password is {}",password);
		//Creating a Token using the informations of a certain request
		UsernamePasswordAuthenticationToken authenticationtoken = new UsernamePasswordAuthenticationToken(username,password);
		//Authenticate the user with the request
		return authenticationManager.authenticate(authenticationtoken);
		
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		

		
	}

	
}
