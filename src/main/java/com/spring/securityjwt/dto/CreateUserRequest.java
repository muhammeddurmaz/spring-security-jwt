package com.spring.securityjwt.dto;

import com.spring.securityjwt.model.Role;
import lombok.Builder;

import java.util.Set;

@Builder
public record CreateUserRequest(
        String username,
        String password,
        Set<Role> authorities
){
}
