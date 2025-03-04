package com.orenda.user_service.service;

import com.orenda.user_service.config.JwtService;
import com.orenda.user_service.dto.PasswordResetRequest;
import com.orenda.user_service.dto.UserProfileUpdateRequest;
import com.orenda.user_service.dto.UserRegistrationRequest;
import com.orenda.user_service.entity.User;
import com.orenda.user_service.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager, UserDetailsService userDetailsService){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @Override
    @Transactional
    public User registerUser(UserRegistrationRequest dto){

        if(existsUserName(dto.getUserName())){
            throw new IllegalArgumentException("User already exists!");
        }
        if(existsEmail(dto.getEmail())){
            throw new IllegalArgumentException("Email already exists!");
        }

        User user = new User();
        user.setUserName(dto.getUserName());
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setPhone(dto.getPhone());
        user.getRoles().add("ROLE_CUSTOMER");
        user.setActivationToken(java.util.UUID.randomUUID().toString());
        user.setActivationTokenExpiry(LocalDateTime.now().plusDays(1)); // token expires in 1 day

        userRepository.save(user);

        //implement send Activation email

        return user;
    }

    @Override
    @Transactional
    public void activateAccount(String token) {
        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired activation token"));

        if(user.getActivationTokenExpiry().isBefore(LocalDateTime.now())){
            throw new IllegalArgumentException("Activation token is expired");
        }

        if(user.isEnabled()){
            throw new IllegalArgumentException("Account is activated");
        }

        user.setEnabled(true);
        user.setAccountActivatedAt(LocalDateTime.now());
        user.setActivationToken(null); //invalidate token
        user.setActivationTokenExpiry(null);
        userRepository.save(user);
    }

    @Override
    public String loginUser(String userName, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName, password));
        User user = userRepository.findByUsername(userName)
                .orElseThrow(()->new IllegalArgumentException("User not found!"));

        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
        String jwtToken = jwtService.generateToken(userDetails);
        String refreshTokenValue = jwtService.generateRefreshToken(userDetails); // <---- Pass UserDetails to generateRefreshToken
        user.setRefreshToken(passwordEncoder.encode(refreshTokenValue)); // Hash refresh token before saving - for security comparison
        userRepository.save(user);

        return jwtToken;
    }

    @Override
    public String refreshToken(String refreshTokenValue) {
        String username = jwtService.extractUsernameFromRefreshToken(refreshTokenValue);
        User user = getUserByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException("Invalid refresh token - user not found"));

        if (!passwordEncoder.matches(refreshTokenValue, user.getRefreshToken())) { // Securely compare hashed refresh token
            throw new IllegalArgumentException("Invalid refresh token - token mismatch"); // Refresh token mismatch
        }

        if (jwtService.isRefreshTokenExpired(refreshTokenValue)) {
            throw new IllegalArgumentException("Refresh token expired"); // Refresh token expired
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return jwtService.generateToken(userDetails); // Generate new JWT access token
    }


    @Override
    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    @Transactional
    public User updateUserProfile(Long id, UserProfileUpdateRequest updateRequest, String currentUsername) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        if (!existingUser.getUserName().equals(currentUsername) && !existingUser.getRoles().contains("ROLE_ADMIN")) {
            throw new SecurityException("Not authorized to update profile for another user"); // Example authorization
        }

        if (updateRequest.getFirstName() != null) existingUser.setFirstName(updateRequest.getFirstName());
        if (updateRequest.getLastName() != null) existingUser.setLastName(updateRequest.getLastName());
        if (updateRequest.getEmail() != null) {
            if (!existingUser.getEmail().equals(updateRequest.getEmail()) && existsEmail(updateRequest.getEmail())) {
                throw new IllegalArgumentException("Email already exists");
            }
            existingUser.setEmail(updateRequest.getEmail());
        }
        if (updateRequest.getPhone() != null) existingUser.setPhone(updateRequest.getPhone());
        // Add more fields to update as needed, ensure proper validation and authorization

        return userRepository.save(existingUser);
    }

    @Override
    @Transactional
    public void deleteUser(Long id, String currentUsername) {
        User userToDelete = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        User requestingUser = getUserByUsername(currentUsername).orElseThrow(() -> new EntityNotFoundException("Current user not found"));

        if (!userToDelete.getUserName().equals(requestingUser.getUserName()) && !requestingUser.getRoles().contains("ROLE_ADMIN")) {
            throw new SecurityException("Not authorized to delete another user's account (unless admin)"); // Example authorization
        }

        userRepository.deleteById(id);
    }

    @Override
    @Transactional
    public void deactivateAccount(Long id, String currentUsername) {
        User userToDeactivate = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        User requestingUser = getUserByUsername(currentUsername).orElseThrow(() -> new EntityNotFoundException("Current user not found"));

        if (!userToDeactivate.getUserName().equals(requestingUser.getUserName())) {
            throw new SecurityException("Not authorized to deactivate another user's account");
        }

        if (!userToDeactivate.isEnabled()) { // Only deactivate if already active
            throw new IllegalStateException("Account is already deactivated");
        }

        userToDeactivate.setAccountNonLocked(false); // Lock account to prevent login
        userToDeactivate.setAccountDeactivatedAt(LocalDateTime.now());
        userRepository.save(userToDeactivate);
    }

    @Override
    @Transactional
    public void reactivateAccount(Long id, String currentUsername) {
        User userToReactivate = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        User requestingUser = getUserByUsername(currentUsername).orElseThrow(() -> new EntityNotFoundException("Current user not found"));

        if (!userToReactivate.getUserName().equals(requestingUser.getUserName())) {
            throw new SecurityException("Not authorized to reactivate another user's account");
        }
        if (userToReactivate.isEnabled()) { // Only reactivate if deactivated
            throw new IllegalStateException("Account is already active");
        }

        userToReactivate.setAccountNonLocked(true); // Unlock account
        userToReactivate.setAccountDeactivatedAt(null); // Clear deactivation timestamp
        userRepository.save(userToReactivate);
    }

    @Override
    @Transactional
    public void disableAccountByAdmin(Long id, String adminUsername) {
        User userToDisable = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("User not found with id: " + id));

        User adminUser = getUserByUsername(adminUsername).orElseThrow(() -> new EntityNotFoundException("Admin user not found"));

        if (!adminUser.getRoles().contains("ROLE_ADMIN")) {
            throw new SecurityException("Only admins are authorized to disable user accounts");
        }

        userToDisable.setAccountNonLocked(false); // Lock account
        userToDisable.setAccountDeactivatedAt(LocalDateTime.now()); // Set deactivation timestamp
        userRepository.save(userToDisable);
    }


    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("User not found with email: " + email));

        String resetToken = UUID.randomUUID().toString();
        user.setActivationToken(resetToken); // Reusing activationToken field for simplicity - ideally separate field for reset token and expiry
        user.setActivationTokenExpiry(LocalDateTime.now().plusHours(1)); // Reset token expires in 1 hour
        userRepository.save(user);

        sendPasswordResetEmail(user, resetToken); // Send password reset email asynchronously
    }

    @Async // Run asynchronously
    private void sendPasswordResetEmail(User user, String resetToken) {
        // In real app, use a proper email sending library/service
        System.out.println("Sending password reset email to: " + user.getEmail());
        System.out.println("Password reset URL: http://localhost:8082/api/users/reset-password?token=" + resetToken);
        // emailService.sendPasswordResetEmail(user.getEmail(), resetToken); // Conceptual email sending
    }

    @Override
    @Transactional
    public void resetPassword(PasswordResetRequest resetRequest) {
        User user = userRepository.findByActivationToken(resetRequest.getToken())
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired reset token"));

        if (user.getActivationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Password reset token expired");
        }

        user.setPassword(passwordEncoder.encode(resetRequest.getNewPassword())); // Hash new password
        user.setActivationToken(null); // Invalidate token
        user.setActivationTokenExpiry(null);
        userRepository.save(user);
    }


    // Conceptual Booking History Fetching (Needs Booking Service Integration)
    // @Override
    // public List<Booking> getBookingHistory(Long userId) {
    //     // In a real app, you would call the Booking Service API to fetch booking history for the user
    //     // using a REST client (e.g., RestTemplate, WebClient) or a dedicated BookingServiceClient
    //     // Example conceptual code:
    //     //   return bookingServiceClient.getBookingHistoryForUser(userId);
    //     throw new UnsupportedOperationException("Booking history fetching not implemented in User Service - needs Booking Service integration");
    // }

//    public LoginResponseDTO loginUser(LoginRequestDTO loginRequestDTO){
//        User user = userRepository.findByEmail(loginRequestDTO.getEmail())
//                .orElseThrow(() -> new RuntimeException("User Not found!"));
//
//        if(!passwordEncoder.matches(loginRequestDTO.getPassword(), user.getPassword())){
//            throw new RuntimeException("Invalid password!");
//        }
//
//        String token = jwtUtil.generateToken(user.getEmail());
//        return new LoginResponseDTO(token, "refreshToken");
//    }
//
//    public String verifyEmail(String token){
//        User user = userRepository.findByVerificationToken(token)
//                .orElseThrow(() -> new RuntimeException("Token is invalid!"));
//
//        user.setEmailVerified(true);
//        user.setVerificationToken(null);
//        userRepository.save(user);
//        return "Email Verified successfully!";
//    }
//
//    public String resetPassword(ResetPasswordDTO resetPasswordDTO){
//        User user = userRepository.findByEmail(resetPasswordDTO.getEmail())
//                .orElseThrow(() -> new RuntimeException("User not found!"));
//
//        user.setResetToken(UUID.randomUUID().toString());
//        return "Password reset link sent";
//    }

    @Override
    public boolean existsUserName(String userName){
        return userRepository.existByUserName(userName);
    }

    @Override
    public boolean existsEmail(String email) {
        return userRepository.existByEmail(email);
    }
}
