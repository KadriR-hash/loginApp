package tn.enicarthage.springboot.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import tn.enicarthage.springboot.modal.User;


public interface UserRepository extends JpaRepository<User,Long> {
	
	 User findByUsername (String username);

}
