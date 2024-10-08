package com.example.userservice.security;

import com.example.userservice.dto.UserDTO;
import com.example.userservice.service.UserService;
import com.example.userservice.vo.RequestLogin;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

@Slf4j
public class AuthenticationFilter  extends UsernamePasswordAuthenticationFilter {

    private UserService userService;
    private Environment env;

    public AuthenticationFilter(AuthenticationManager authenticationManager,
                                   UserService userService, Environment environment) {
        super(authenticationManager);
        this.userService = userService;
        this.env = environment;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException {
        try {

            RequestLogin creds = new ObjectMapper().readValue(req.getInputStream(), RequestLogin.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getPassword(), new ArrayList<>()));

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String userName = ((User)authResult.getPrincipal()).getUsername();
        UserDTO userDetails =  userService.getUserDetailsByEmail(userName);

        Instant now = Instant.now();


        byte[] secretKeyBytes = Base64.getEncoder().encode(env.getProperty("token.secret").getBytes());
        SecretKey key = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());

        String token = Jwts.builder()
                .setSubject(userDetails.getUserId())
                .setExpiration(Date.from(now.plusMillis(Long.parseLong(env.getProperty("token.expiration_time")))))
                .setIssuedAt(Date.from(now))
                .signWith(key, SignatureAlgorithm.HS512) // HS256으로 서명
                .compact();

        response.addHeader("token", token);
        response.addHeader("userId", userDetails.getUserId());
    }
}
