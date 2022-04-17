package com.uniovi.sdi2122317spring;

import com.uniovi.sdi2122317spring.entities.CustomOAuth2User;
import com.uniovi.sdi2122317spring.services.CustomOAuth2UserService;
import com.uniovi.sdi2122317spring.services.UserServiceGoogle;
import com.uniovi.sdi2122317spring.services.UsersService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.thymeleaf.extras.springsecurity4.dialect.SpringSecurityDialect;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private UserServiceGoogle usersService;
    @Autowired
    private CustomOAuth2UserService oauthUserService;

    @Bean
    public SpringSecurityDialect securityDialect() {
        return new SpringSecurityDialect();
    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }




    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/css/**", "/images/**", "/script/**", "/", "/signup", "/login/**", "/oauth/**").permitAll()
                .antMatchers("/mark/add").hasAuthority("ROLE_PROFESSOR")
                .antMatchers("/mark/edit/*").hasAuthority("ROLE_PROFESSOR")
                .antMatchers("/mark/delete/*").hasAuthority("ROLE_PROFESSOR")
                .antMatchers("/mark/**").hasAnyAuthority("ROLE_STUDENT", "ROLE_PROFESSOR", "ROLE_ADMIN")
                .antMatchers("/user/**").hasAnyRole("ADMIN")
                .antMatchers("/professor/details/*").hasAnyAuthority("ROLE_ADMIN", "ROLE_PROFESSOR")
                .antMatchers("/professor/edit/*").hasAuthority("ROLE_ADMIN")
                .antMatchers("/professor/delete/*").hasAuthority("ROLE_ADMIN")
                .antMatchers("/professor/add").hasAuthority("ROLE_ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll().and()
                .oauth2Login()
                .loginPage("/login")
                .userInfoEndpoint()
                .userService(oauthUserService).and()
                .defaultSuccessUrl("/home")
                .and()
                .logout()
                .permitAll();

        http.oauth2Login()
                .loginPage("/login")
                .userInfoEndpoint()
                .userService(oauthUserService)
                .and()
                .successHandler(new AuthenticationSuccessHandler() {

                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                        Authentication authentication) throws IOException, ServletException {

                        CustomOAuth2User oauthUser = (CustomOAuth2User) authentication.getPrincipal();

                        usersService.processOAuthPostLogin(oauthUser.getEmail());

                        response.sendRedirect("/");
                    }
                });
    }

    //  @Autowired
    //    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    //     auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    // }

}

