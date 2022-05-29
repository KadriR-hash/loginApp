package tn.enicarthage.springboot.security;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
// UsernamePasswordAuthenticationFilter Contains the default login given by the spring security
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
			Authentication authentication) throws IOException, ServletException {
		
		User user = (User)authentication.getPrincipal();	
		Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
		// Create access Token
		String access_token = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+ 10 * 60 * 1000))
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.sign(algorithm);
		
		String refresh_token = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+ 30 * 60 * 1000))
				.withIssuer(request.getRequestURL().toString())
				.sign(algorithm);
				
		
		// Send those to the user in to the Front
		
		//response.setHeader("access_token", access_token);
		//response.setHeader("refresh_token", refresh_token); 
		
		// The Body in Postman will contain the value of the map in a nice JSON format
		Map<String,String> tokens = new HashMap<>();
		tokens.put("access_token", access_token);
		tokens.put("refresh_token", refresh_token);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		new ObjectMapper().writeValue(response.getOutputStream(),tokens);
		
	}

	
}
