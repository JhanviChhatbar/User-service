package com.orenda.user_service.service;

import com.orenda.user_service.dto.UserRegistrationRequest;
import com.orenda.user_service.entity.User;

public interface UserService {

    User registerUser(UserRegistrationRequest userRegistrationRequest);
    boolean existsUserName(String userName);
    boolean existsEmail(String email);
    void activateAccount(String token);
    String loginUser(String userName, String password); // returns JWT token
//    String refreshToken(String refreshTokenValue);

}
