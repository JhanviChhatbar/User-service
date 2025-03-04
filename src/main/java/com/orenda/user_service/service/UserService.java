package com.orenda.user_service.service;

import com.orenda.user_service.dto.PasswordResetRequest;
import com.orenda.user_service.dto.UserProfileUpdateRequest;
import com.orenda.user_service.dto.UserRegistrationRequest;
import com.orenda.user_service.entity.User;

import java.util.Optional;

public interface UserService {

    User registerUser(UserRegistrationRequest userRegistrationRequest);
    boolean existsUserName(String userName);
    boolean existsEmail(String email);
    void activateAccount(String token);
    String loginUser(String userName, String password); // returns JWT token
    String refreshToken(String refreshTokenValue); // Returns new JWT token
    Optional<User> getUserByUsername(String username);
    Optional<User> getUserById(Long id);
    User updateUserProfile(Long id, UserProfileUpdateRequest updateRequest, String currentUsername); // Profile update
    void deleteUser(Long id, String currentUsername); // User or Admin initiated delete
    void deactivateAccount(Long id, String currentUsername);
    void reactivateAccount(Long id, String currentUsername);
    void disableAccountByAdmin(Long id, String adminUsername); // Admin can disable
    void requestPasswordReset(String email);
    void resetPassword(PasswordResetRequest resetRequest);


}
