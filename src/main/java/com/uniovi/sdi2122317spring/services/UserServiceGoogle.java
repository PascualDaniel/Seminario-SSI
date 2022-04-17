package com.uniovi.sdi2122317spring.services;

import com.uniovi.sdi2122317spring.entities.Provider;
import com.uniovi.sdi2122317spring.entities.User;
import com.uniovi.sdi2122317spring.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceGoogle {

    @Autowired
    private UserRepository repo;
    public void processOAuthPostLogin(String username) {
        User existUser = repo.getUserByUsername(username);

        if (existUser == null) {
            User newUser = new User();
            newUser.setUsername(username);
            newUser.setProvider(Provider.GOOGLE);
            newUser.setEnabled(true);

            repo.save(newUser);
        }

    }

}
