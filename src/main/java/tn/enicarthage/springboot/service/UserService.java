package tn.enicarthage.springboot.service;

import java.util.List;

import tn.enicarthage.springboot.modal.Role;
import tn.enicarthage.springboot.modal.User;

public interface UserService {
	
	User saveUser (User user);
	Role saveRole (Role role);
	void addRoleToUser (String username , String rolename);
	User getUser ( String username);
	List<User> getUsers();
}

