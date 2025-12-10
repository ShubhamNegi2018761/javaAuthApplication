package com.substring.auth.services.impl;

import com.substring.auth.dtos.UserDto;
import com.substring.auth.entities.Provider;
import com.substring.auth.entities.User;
import com.substring.auth.exceptions.ResourceNotFoundException;
import com.substring.auth.helpers.UserHelper;
import com.substring.auth.repositories.UserRepository;
import com.substring.auth.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {
        //convert this dto to entity and then create/ save user

        if(userDto.getEmail()==null || userDto.getEmail().isBlank()){
            throw new IllegalArgumentException("Email is required");
        }

        if (userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("Email is already exists");
        }

        //if you have extra checks __put here....

        User user=modelMapper.map(userDto, User.class);

        user.setProvider(userDto.getProvider()!=null ? userDto.getProvider(): Provider.LOCAL);

        //role assign here to new User for authorization
        //todo
        User savedUser=userRepository.save(user);

        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {

        User user=userRepository
                .findByEmail(email)
                .orElseThrow(()->new ResourceNotFoundException("User Not Found with given email id"));

        return modelMapper.map(user,UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uid=UserHelper.parseUUID(userId);
        User existingUser=userRepository
                .findById(uid)
                .orElseThrow(()->new ResourceNotFoundException("User Not found with given id"));
        // we can not update email id for this project

        if (userDto.getName()!=null) existingUser.setName(userDto.getName());
        if (userDto.getImage()!=null) existingUser.setImage(userDto.getImage());
        if (userDto.getProvider()!=null) existingUser.setProvider(userDto.getProvider());

        //todo : change password updation logic , as password is encoded , hashed
        if (userDto.getPassword()!=null) existingUser.setPassword(userDto.getPassword());
        existingUser.setEnable(userDto.isEnable());
        existingUser.setUpdatedAt(Instant.now());

        User updateUser=userRepository.save(existingUser);

        return modelMapper.map(updateUser, UserDto.class);
    }

    @Override
    @Transactional
    public void deleteUser(String userId) {
        //parese String to UUID
        UUID uId= UserHelper.parseUUID(userId);
        User user=userRepository.findById(uId).orElseThrow(()->new ResourceNotFoundException("User Not found with the given ID"));
        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user=userRepository.findById(UserHelper.parseUUID(userId)).orElseThrow(()->new ResourceNotFoundException("User Not found with the given ID"));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
}
