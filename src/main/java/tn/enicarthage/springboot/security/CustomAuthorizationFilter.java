package tn.enicarthage.springboot.security;


import java.io.IOException;
import java.util.*;
import java.util.stream.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter{
	//Validation of the token
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		//Try to log in
		if(request.getServletPath().equals("/api/login") ||request.getServletPath().equals("/api/token/refresh")) {
				//Basically don't do anything , just let the request go through
				filterChain.doFilter(request, response);
		}
		else {
			//Header is the key for a token
			String authorizationheader =request.getHeader(HttpHeaders.AUTHORIZATION);
			//when the log in is successful the front send a token x to the back and the back send a token to the front
			//with the word "bearer "+the token x
			//bearer = its their own token = validated
			if(authorizationheader != null && authorizationheader.startsWith("Bearer ")) {
				try {
				String token = authorizationheader.substring("Bearer ".length());//Remove the "Bearer "
				Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());//Same "secret"
				JWTVerifier verifier = JWT.require(algorithm).build();
				DecodedJWT decodedJWT = verifier.verify(token);
				String username = decodedJWT.getSubject();
				String[] roles = decodedJWT.getClaim("roles").asArray(String.class);//the key is roles is roles
				//We don't need password because the user is already authenticated (token is valid)
				Collection<SimpleGrantedAuthority>	authorities = new ArrayList<>();
				stream(roles).forEach(role ->{
						authorities.add(new SimpleGrantedAuthority(role));
				});
				
				UsernamePasswordAuthenticationToken authenticationtoken = 
						new UsernamePasswordAuthenticationToken(username,null,authorities);//We don't need password ,
																						   //and we don't have it either 
				//telling spring security here is the user + his roles and what he can do in the application
				SecurityContextHolder.getContext().setAuthentication(authenticationtoken);
				filterChain.doFilter(request, response);//continue
				}
				catch(Exception exception) {
					log.error("Error logging in : {}",exception.getMessage());
					response.setHeader("error", exception.getMessage());
					response.setStatus(HttpStatus.FORBIDDEN.value());
					//response.sendError(HttpStatus.FORBIDDEN.value());
					Map<String,String> error = new HashMap<>();
					error.put("error_message", exception.getMessage());
					response.setContentType(MediaType.APPLICATION_JSON_VALUE);
					new ObjectMapper().writeValue(response.getOutputStream(),error);
			}
				
			}
			else {
				filterChain.doFilter(request, response);//continue

			}
			
		}
	}


}
