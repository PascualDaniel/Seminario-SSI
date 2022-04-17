package com.uniovi.sdi2122317spring.repositories;

import com.uniovi.sdi2122317spring.entities.Professor;
import org.springframework.data.repository.CrudRepository;

public interface ProfessorsRepository extends CrudRepository<Professor, Long>{

    Professor findByDni(String dni);

}
