package com.orenda.user_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.PublicKey;
import java.util.Date;

@Component
public class JwtUtil {

    private static final String SECRET_KEY = "";

    private Key getSigningKey(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
    }

    public String generateToken(String email){
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 *10)) //10 hours expiry
                .signWith(getSigningKey())
                .compact();
    }

    public String extractEmail(String token){
        
            Claims claims = Jwts.parser()
                    .verifyWith((PublicKey) getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getSubject();

    }
}
