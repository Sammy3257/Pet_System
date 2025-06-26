package com.Pets_System.Pets_System.controller;


import com.Pets_System.Pets_System.dto.LoginRequest;
import com.Pets_System.Pets_System.dto.RegisterRequest;
import com.Pets_System.Pets_System.model.User;
import com.Pets_System.Pets_System.repository.UserRepository;
import com.Pets_System.Pets_System.security.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.auth.oauth2.GooglePublicKeysManager;
import com.google.api.client.http.javanet.NetHttpTransport;

import java.util.Collections;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;


import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> Registration(@RequestBody RegisterRequest request){
        Map<String, String> response = new HashMap<>();

        if (userRepository.existsByEmail(request.getEmail())){
            response.put("message", "Email already exist");
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(response);
        }

        User newUser = new User();
        newUser.setName(request.getName());
        newUser.setEmail(request.getEmail());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(newUser);
        response.put("message", "Registration successful");
        return ResponseEntity.ok(response);
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request){
        Map<String, String> response = new HashMap<>();

        User user = userRepository.findByEmail(request.getEmail());

        if(user != null && passwordEncoder.matches(request.getPassword(), user.getPassword())){
            String token = jwtUtil.generateToken(user.getEmail());
            response.put("message","Login in successful");
            response.put("token", token);
        }else {
            response.put("message","invalid credentials");
        }
        return ResponseEntity.ok(response);
    }


    @GetMapping("/token")
    public ResponseEntity<?> getToken(HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User user) {
            String email = user.getAttribute("email");
            String token = jwtUtil.generateToken(email);

            response.put("message","Login successful");
            response.put("token", token);
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not authenticated");
    }



}
