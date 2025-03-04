package com.orenda.user_service.dto;

import lombok.Data;

@Data
public class UserProfileUpdateRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
}
