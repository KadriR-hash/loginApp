package tn.enicarthage.springboot.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


import javax.transaction.Transactional;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tn.enicarthage.springboot.modal.Role;
import tn.enicarthage.springboot.modal.User;
import tn.enicarthage.springboot.repo.RoleRepo;
import tn.enicarthage.springboot.repo.UserRepository;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImp implements UserService , UserDetailsService {

	
	private  final UserRepository userRepo;
	private  final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user = userRepo.findByUsername(username);
		if(user == null) {
			log.error("User Not Found");
			throw new UsernameNotFoundException("User Not Found");}
		else {
			log.info("User found in Database {}",username);
		}
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role ->
		{ 
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword() , authorities);
	}
	
	@Override
	public User saveUser(User user) {
		
		log.info("Saving new user {}",user.getUsername());
		// Encoding the password
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {}",role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String rolename) {
		log.info("Adding role {} to user {}",rolename ,username);
		User user = userRepo.findByUsername(username);
		Role role = roleRepo.findByName(rolename);
		user.getRoles().add(role);
		
	}

	@Override
	public User getUser(String username) {
		log.info("Fetching user {}",username);
		return userRepo.findByUsername(username);
	}

	@Override
	public List<User> getUsers() {
		log.info("Fetching all users");
		return userRepo.findAll();
	}



	
}
