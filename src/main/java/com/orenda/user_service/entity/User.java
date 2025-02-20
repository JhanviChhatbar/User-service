package com.orenda.user_service.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true,nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String userName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    private boolean enabled = false; //For activation
    private LocalDateTime accountActivatedAt; //Track time of activation

    private String activationToken;
    private LocalDateTime activationTokenExpiry;

    private boolean accountNonLocked = true; // For account deactivation/admin disable
    private LocalDateTime accountDeactivatedAt;

    private String resetToken;

    private String firstName;
    private String lastName;
    private String phone;

    public enum Role{
        CUSTOMER, ADMIN, EVENT_ORGANIZER
    }

}
