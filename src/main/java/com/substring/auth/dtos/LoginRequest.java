package com.substring.auth.dtos;

public record LoginRequest(
        String email,
        String password
) {

}
