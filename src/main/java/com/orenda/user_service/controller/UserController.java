package com.orenda.user_service.controller;

import com.orenda.user_service.dto.UserRegistrationRequest;
import com.orenda.user_service.entity.User;
import com.orenda.user_service.service.UserService;
import com.orenda.user_service.service.UserServiceImpl;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserServiceImpl userService){
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<User> registerNewUser(@Valid @RequestBody UserRegistrationRequest userRegistrationRequest){
        User registeredUser = userService.registerUser(userRegistrationRequest);
        return new ResponseEntity<>(registeredUser, HttpStatus.CREATED);
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activateUserAccount(@RequestParam String token){
        userService.activateAccount(token);
        return ResponseEntity.ok("Account activated successfully! You can now login.");
    }
}
