package com.orenda.user_service.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import io.micrometer.observation.ObservationRegistry; // Example for observability - import Micrometer

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    // private final ObservationRegistry observationRegistry; // Example for observability - Inject ObservationRegistry

    @Autowired
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) { //, ObservationRegistry observationRegistry) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        // this.observationRegistry = observationRegistry; // Example for observability
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // Continue filter chain - not a JWT request
            return;
        }

        jwtToken = authHeader.substring(7); // Extract token after "Bearer "

        // Observation.createNotStarted("jwt.token.extraction", observationRegistry).lowCardinalityKeyValue("outcome", "success").start().scoped(() -> { // Example Observability with Micrometer
        username = jwtService.extractUserName(jwtToken); // Extract username from JWT
        // });


        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) { // Username extracted and no existing authentication
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtService.isValidToken(jwtToken, userDetails)) { // Validate token
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // No credentials needed as token is validated
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // Add request details
                SecurityContextHolder.getContext().setAuthentication(authToken); // Set authentication in Security Context
                // Observation.event("jwt.authentication.success").scoped(() -> {}); // Example Observability - Log success
            } // else { Observation.event("jwt.authentication.failed").scoped(() -> {}); } // Example Observability - Log failure (invalid token)
        }

        filterChain.doFilter(request, response); // Continue filter chain
    }
}
