package com.orenda.user_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import jakarta.persistence.EntityNotFoundException;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice // Handles exceptions globally in controllers
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class) // For bad requests (e.g., invalid input)
    public ResponseEntity<Map<String, String>> handleIllegalArgumentException(IllegalArgumentException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", ex.getMessage());
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST); // 400 Bad Request
    }

    @ExceptionHandler(EntityNotFoundException.class) // For resource not found
    public ResponseEntity<Map<String, String>> handleEntityNotFoundException(EntityNotFoundException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", ex.getMessage());
        return new ResponseEntity<>(errors, HttpStatus.NOT_FOUND); // 404 Not Found
    }

    @ExceptionHandler(SecurityException.class) // For authorization failures
    public ResponseEntity<Map<String, String>> handleSecurityException(SecurityException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", ex.getMessage());
        return new ResponseEntity<>(errors, HttpStatus.FORBIDDEN); // 403 Forbidden (or 401 Unauthorized depending on scenario)
    }

    @ExceptionHandler(IllegalStateException.class) // For invalid state transitions (e.g., activating already active account)
    public ResponseEntity<Map<String, String>> handleIllegalStateException(IllegalStateException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", ex.getMessage());
        return new ResponseEntity<>(errors, HttpStatus.CONFLICT); // 409 Conflict - appropriate for state conflict
    }

    @ExceptionHandler(MethodArgumentNotValidException.class) // For validation errors in request bodies (@Valid)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->errors.put(error.getField(), error.getDefaultMessage())
        );
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST); // 400 Bad Request for validation errors
    }

    // Add more exception handlers for other specific exceptions you might throw
    @ExceptionHandler(Exception.class) // Generic fallback exception handler
    public ResponseEntity<Map<String, String>> handleGenericException(Exception ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put("error", "An unexpected error occurred."); // Generic message - for security, don't expose detailed error info in production
        // Log the full exception details for debugging in your centralized logging (Coralogix)
        ex.printStackTrace(); // For development logging to console - remove in production
        return new ResponseEntity<>(errors, HttpStatus.INTERNAL_SERVER_ERROR); // 500 Internal Server Error
    }
}
