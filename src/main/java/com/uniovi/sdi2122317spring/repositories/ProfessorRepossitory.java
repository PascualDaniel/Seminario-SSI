package com.uniovi.sdi2122317spring.repositories;

import com.uniovi.sdi2122317spring.entities.Mark;
import com.uniovi.sdi2122317spring.entities.Professor;
import org.springframework.data.repository.CrudRepository;

public interface ProfessorRepossitory extends CrudRepository<Professor, Long> {
}
