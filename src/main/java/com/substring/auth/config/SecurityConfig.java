package com.substring.auth.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Map;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //why we need to disable csrf token
        http.csrf(AbstractHttpConfigurer::disable)
        .cors(Customizer.withDefaults())
                .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                authorizeHttpRequests->
                        authorizeHttpRequests.requestMatchers("/api/v1/auth/register").permitAll()
                                .requestMatchers("/api/v1/auth/login").permitAll()
                                .anyRequest().authenticated()
        )
                .exceptionHandling(ex->ex.authenticationEntryPoint((request,response,e)->{

                    e.printStackTrace();
                    response.setStatus(401);
                    response.setContentType("application/json");
                    String msg="Unauthorized access "+e.getMessage();

                            //Make Json
                            Map<String,String>errorMap=Map.of("message",msg,"status",String.valueOf(401),"statusCode",new Integer(401).toString());
                            //json string
                    var objectMapper=new ObjectMapper();
                    response.getWriter().write(objectMapper.writeValueAsString(errorMap));
                        }
                        //error message
                        ));
    //only basic authentication

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService user(){
//        // The builder will ensure the passwords are encoded before saving in memory
//
//        //User is the implementation class of UserDetails
//        User.UserBuilder userBuilder= User.withDefaultPasswordEncoder();
//
//        UserDetails user1 = userBuilder
//                .username("ankit")
//                .password("abc")
//                .roles("ADMIN")
//                .build();
//        UserDetails user2 = userBuilder
//                .username("shiva")
//                .password("xyz")
//                .roles("USER","ADMIN")
//                .build();
//
//        //implementation class of UserDetails class
//        return new InMemoryUserDetailsManager(user1,user2);
//    }





}
