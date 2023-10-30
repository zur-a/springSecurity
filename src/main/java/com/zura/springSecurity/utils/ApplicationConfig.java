package com.zura.springSecurity.utils;

import com.zura.springSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository repository;
    @Bean
    public UserDetailsService userDetailsService() {
        return emailUsername -> repository
                                    .findByEmail(emailUsername)
                                    .orElseThrow(() -> new UsernameNotFoundException("Username not found"));
    }
}
