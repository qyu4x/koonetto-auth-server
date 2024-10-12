package com.koonetto.authserver.service;

import com.koonetto.authserver.request.CreateUserRequest;
import com.koonetto.authserver.response.CreateUserResponse;
import org.springframework.security.core.userdetails.UserDetails;

public interface KoonettoAuthenticationService {
    UserDetails loadUserByEmail(String email);

    CreateUserResponse register(CreateUserRequest request);
}
