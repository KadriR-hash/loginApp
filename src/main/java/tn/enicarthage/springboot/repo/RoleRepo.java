package tn.enicarthage.springboot.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import tn.enicarthage.springboot.modal.Role;

public interface RoleRepo extends JpaRepository<Role,Long>{

	Role findByName (String name);

}
