package com.zura.springSecurity.service;

import com.zura.springSecurity.model.Role;
import com.zura.springSecurity.model.User;
import com.zura.springSecurity.repository.UserRepository;
import com.zura.springSecurity.request.AuthenticationRequest;
import com.zura.springSecurity.request.RegisterRequest;
import com.zura.springSecurity.response.AuthenticationResponse;
import com.zura.springSecurity.utils.PasswordEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final BCryptPasswordEncoder encoder;
    private final JwtService jwtService;
    private final AuthenticationManager manager;
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User
                .builder()
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .email(request.getEmail())
                    .password(encoder.encode(request.getPassword()))
                    .role(Role.USER)
                .build();
        repository.save(user);

        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse
                .builder()
                    .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        manager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse
                .builder()
                    .token(jwtToken)
                .build();
    }
}
