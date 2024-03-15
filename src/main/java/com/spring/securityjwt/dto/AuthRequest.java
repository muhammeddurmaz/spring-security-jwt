package com.spring.securityjwt.dto;

public record AuthRequest(
        String username,
        String password
) {
}
