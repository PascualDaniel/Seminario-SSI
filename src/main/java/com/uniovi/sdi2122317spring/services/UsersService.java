package com.uniovi.sdi2122317spring.services;

import java.util.*;
import javax.annotation.PostConstruct;

import com.uniovi.sdi2122317spring.entities.User;
import com.uniovi.sdi2122317spring.repositories.UsersRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsersService {
    @Autowired
    private UsersRepository usersRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostConstruct
    public void init() {
    }
    public List<User> getUsers() {
        List<User> users = new ArrayList<User>();
        usersRepository.findAll().forEach(users::add);
        return users;
    }
    public User getUser(Long id) {
        return usersRepository.findById(id).get();
    }
    public void addUser(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        usersRepository.save(user);
    }
    public User getUserByDni(String dni) {
        return usersRepository.findByDni(dni);
    }
    public void deleteUser(Long id) {
        usersRepository.deleteById(id);
    }

   /* public void editUser(User user){
        if(usersRepository.findById(user.getId()).isPresent()){
            User user2 = usersRepository.findById(user.getId()).get();
            user2.setMarks(user.getMarks());
            user2.setDni(user.getDni());
            user2.setRole(user.getRole());
            user2.setName(user.getName());
            user2.setLastName(user.getLastName());

        }

    }*/
}