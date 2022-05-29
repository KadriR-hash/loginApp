package tn.enicarthage.springboot.conroler;


import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tn.enicarthage.springboot.modal.Role;
import tn.enicarthage.springboot.modal.User;
import tn.enicarthage.springboot.security.CustomAuthorizationFilter;
import tn.enicarthage.springboot.service.UserService;
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AppController {
	
	private  final UserService userService;
	
	@GetMapping("/users")
	public ResponseEntity<List<User>> getUsers(){
		return ResponseEntity.ok().body(userService.getUsers()); 
	}
	
	@PostMapping("/user/save")
	public ResponseEntity<User> saveUser(@RequestBody User user){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveUser(user)); 
	}
	
	@PostMapping("/role/save")
	public ResponseEntity<Role> saveRole(@RequestBody Role role){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());

		return ResponseEntity.created(uri).body(userService.saveRole(role)); 
	}
	
	@PostMapping("/role/addtouser")
	public ResponseEntity<?> saveRoleToUser(@RequestBody RoleToUserForm form){
		
		userService.addRoleToUser(form.getUsername(),form.getRolename());
		return ResponseEntity.ok().build(); 
	}
	
	@GetMapping("/token/refresh")
	public void  refreshToken(HttpServletRequest request, HttpServletResponse response) throws StreamWriteException, DatabindException, IOException{

		String authorizationheader =request.getHeader(HttpHeaders.AUTHORIZATION);
		if(authorizationheader != null && authorizationheader.startsWith("Bearer ")) {
			try {
			String refresh_token = authorizationheader.substring("Bearer ".length());
			Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
			JWTVerifier verifier = JWT.require(algorithm).build();
			DecodedJWT decodedJWT = verifier.verify(refresh_token);
			String username = decodedJWT.getSubject();
			
			User user = userService.getUser(username);
			
			
			String access_token = JWT.create()
					.withSubject(user.getUsername())
					.withExpiresAt(new Date(System.currentTimeMillis()+ 10 * 60 * 1000))
					.withIssuer(request.getRequestURL().toString())
					.withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
					.sign(algorithm);
			

			Map<String,String> tokens = new HashMap<>();
			tokens.put("access_token", access_token);
			tokens.put("refresh_token", refresh_token);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			new ObjectMapper().writeValue(response.getOutputStream(),tokens);

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
				throw new RuntimeException("Fresh Token is missing");
		}

	}
	
	@Data
	class RoleToUserForm{
		private String username;
		private String rolename;
	}

	
	
}

