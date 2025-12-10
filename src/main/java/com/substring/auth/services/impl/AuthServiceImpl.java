package com.substring.auth.services.impl;

import com.substring.auth.dtos.UserDto;
import com.substring.auth.services.AuthService;
import com.substring.auth.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDto registerUser(UserDto userDto) {

        //verifying email
        //verifying password
        //role assign - default role
        userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
        UserDto userDto1=userService.createUser(userDto);

        return userDto1;
    }
}
