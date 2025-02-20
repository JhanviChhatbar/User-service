package com.orenda.user_service.repository;

import com.orenda.user_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String userName);
    Optional<User> findByEmail(String email);
    boolean existByUserName(String userName);
    boolean existByEmail(String email);
    Optional<User> findByActivationToken(String token);
    Optional<User> findByResetToken(String token);
}
