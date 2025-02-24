package com.orenda.user_service.service;

import com.orenda.user_service.dto.LoginRequestDTO;
import com.orenda.user_service.dto.LoginResponseDTO;
import com.orenda.user_service.dto.UserRegistrationRequest;
import com.orenda.user_service.dto.ResetPasswordDTO;
import com.orenda.user_service.entity.User;
import com.orenda.user_service.repository.UserRepository;
import com.orenda.user_service.util.JwtUtil;
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
    private final JwtUtil jwtUtil;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil){
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
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
