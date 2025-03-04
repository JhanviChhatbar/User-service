package com.orenda.user_service.controller;

import com.orenda.user_service.dto.PasswordResetRequest;
import com.orenda.user_service.dto.UserLoginRequest;
import com.orenda.user_service.dto.UserProfileUpdateRequest;
import com.orenda.user_service.dto.UserRegistrationRequest;
import com.orenda.user_service.entity.User;
import com.orenda.user_service.service.UserService;
import com.orenda.user_service.service.UserServiceImpl;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserServiceImpl userService){
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<User> registerNewUser(@Valid @RequestBody UserRegistrationRequest userRegistrationRequest){ //send back UserResponse dto
        User registeredUser = userService.registerUser(userRegistrationRequest);
        return new ResponseEntity<>(registeredUser, HttpStatus.CREATED);
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activateUserAccount(@RequestParam String token){
        userService.activateAccount(token);
        return ResponseEntity.ok("Account activated successfully! You can now login.");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody @Valid UserLoginRequest loginRequest) { // Use LoginRequest DTO
        String jwtToken = userService.loginUser(loginRequest.getUsername(), loginRequest.getPassword());
        return ResponseEntity.ok(jwtToken); // Return JWT token in response body
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<String> refreshToken(@RequestBody String refreshToken) { // Expect refresh token in request body
        String newAccessToken = userService.refreshToken(refreshToken);
        return ResponseEntity.ok(newAccessToken); // Return new access token
    }

    @GetMapping("/me") // Get current user's profile
    @PreAuthorize("isAuthenticated()") // Secure endpoint for authenticated users
    public ResponseEntity<User> getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName(); // Get username from JWT
        Optional<User> user = userService.getUserByUsername(username);
        return user.map(ResponseEntity::ok)
                .orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    @PutMapping("/me") // Update own profile
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<User> updateCurrentUserProfile(@Valid @RequestBody UserProfileUpdateRequest updateRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        Optional<User> currentUserOptional = userService.getUserByUsername(username);
        return currentUserOptional.map(currentUser -> {
            User updatedUser = userService.updateUserProfile(currentUser.getId(), updateRequest, username);
            return ResponseEntity.ok(updatedUser);
        }).orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }


    @DeleteMapping("/me") // Delete own account
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Void> deleteCurrentUserAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        Optional<User> currentUserOptional = userService.getUserByUsername(username);
        currentUserOptional.ifPresent(currentUser -> userService.deleteUser(currentUser.getId(), username));
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<String> forgotPasswordRequest(@RequestParam String email) {
        userService.requestPasswordReset(email);
        return ResponseEntity.ok("Password reset link sent to your email if the account exists."); // Generic message for security
    }

    @PostMapping("/password/reset")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetRequest resetRequest) {
        userService.resetPassword(resetRequest);
        return ResponseEntity.ok("Password reset successfully.");
    }

    @PostMapping("/deactivate")
    @PreAuthorize("isAuthenticated()") // User initiated deactivation
    public ResponseEntity<String> deactivateCurrentUserAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        Optional<User> currentUserOptional = userService.getUserByUsername(username);
        currentUserOptional.ifPresent(currentUser -> userService.deactivateAccount(currentUser.getId(), username));
        return ResponseEntity.ok("Account deactivated successfully.");
    }

    @PostMapping("/reactivate")
    @PreAuthorize("isAuthenticated()") // User initiated reactivation
    public ResponseEntity<String> reactivateCurrentUserAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        Optional<User> currentUserOptional = userService.getUserByUsername(username);
        currentUserOptional.ifPresent(currentUser -> userService.reactivateAccount(currentUser.getId(), username));
        return ResponseEntity.ok("Account reactivated successfully.");
    }


    // --- Admin Endpoints --- (Secured with ROLE_ADMIN)

    @DeleteMapping("/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')") // Only ADMIN role can access
    public ResponseEntity<Void> deleteUserByAdmin(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String adminUsername = authentication.getName();
        userService.deleteUser(id, adminUsername); // Admin initiated delete
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/admin/users/{id}/disable")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> disableUserAccountByAdmin(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String adminUsername = authentication.getName();
        userService.disableAccountByAdmin(id, adminUsername);
        return ResponseEntity.ok("User account disabled by admin.");
    }

    // Add more admin endpoints as needed (e.g., list users, manage roles, etc.)

    // Conceptual Booking History Endpoint (Needs Booking Service Integration)
    // @GetMapping("/me/bookings")
    // @PreAuthorize("isAuthenticated()")
    // public ResponseEntity<List<Booking>> getCurrentUserBookingHistory() {
    //     Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    //     String username = authentication.getName();
    //     Optional<User> currentUserOptional = userService.getUserByUsername(username);
    //     return currentUserOptional.map(currentUser -> {
    //         List<Booking> bookingHistory = userService.getBookingHistory(currentUser.getId()); // Conceptual Booking History fetch
    //         return ResponseEntity.ok(bookingHistory);
    //     }).orElse(new ResponseEntity<>(HttpStatus.NOT_FOUND));
    // }

}
