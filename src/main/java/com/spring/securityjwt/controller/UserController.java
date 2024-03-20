package com.spring.securityjwt.controller;

import com.spring.securityjwt.dto.AuthRequest;
import com.spring.securityjwt.dto.CreateUserRequest;
import com.spring.securityjwt.model.User;
import com.spring.securityjwt.security.JwtProvider;
import com.spring.securityjwt.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j
public class UserController {

    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;

    public UserController(UserService userService, JwtProvider jwtProvider, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.jwtProvider = jwtProvider;
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/welcome")
    public String welcome() {
        return "Hello World! Welcome to Spring Security JWT";
    }
    @PostMapping("/user")
    public User createUser(@RequestBody CreateUserRequest request) {
        return userService.createUser(request);
    }
    @PostMapping("/authenticate")
    public String authenticate(@RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        if(authentication.isAuthenticated()){
            return jwtProvider.createToken(authentication);
        }
        log.info("Authentication Failed" + request.username());
        throw new UsernameNotFoundException("User not found" + request.username());
    }
    @GetMapping("/user-role")
    public String getUserString(){
        return "Hello User";
    }

    @GetMapping("/admin")
    public String getAdminString(){
        return "Hello Admin";
    }
}
