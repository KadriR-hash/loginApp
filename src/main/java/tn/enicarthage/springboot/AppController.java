package tn.enicarthage.springboot;


import java.net.URI;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import lombok.Data;
import lombok.RequiredArgsConstructor;

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
	
	@Data
	class RoleToUserForm{
		private String username;
		private String rolename;
	}
/*	@GetMapping("")
	public String ViewHomePage() {
		return "index";
	}
	@GetMapping("/register")
	public String showSignUpForm(Model model ) {
		model.addAttribute("user", new User());
		return "signup_form";
	}
	@PostMapping("/process_register")
	public String processRegistration(User user) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String  encodedPassword = encoder.encode(user.getPassword());
		user.setPassword(encodedPassword);
		repo.save(user);
		return "register_success";
	}
	@GetMapping("/list_users")
	public String listUsers(Model model) {
	    List<User> listUsers = repo.findAll();
	    model.addAttribute("listUsers", listUsers);
	     
	    return "users";
	}
*/
	
	
}

