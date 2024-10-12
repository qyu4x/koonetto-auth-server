package com.koonetto.authserver.service;

import com.koonetto.authserver.entity.Authority;
import com.koonetto.authserver.entity.Role;
import com.koonetto.authserver.entity.User;
import com.koonetto.authserver.repository.UserRepository;
import com.koonetto.authserver.request.CreateUserRequest;
import com.koonetto.authserver.response.CreateUserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class KoonettoAuthenticationServiceImpl implements UserDetailsService, KoonettoAuthenticationService {

    private final UserRepository userRepository;

    private final AuthorityService authorityService;

    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        GrantedAuthority authority = new SimpleGrantedAuthority(user.getAuthority().getName().name());
        return new org.springframework.security.core.userdetails.User(user.getEmail(),
                user.getPassword(), Collections.singletonList(authority));
    }

    @Override
    public UserDetails loadUserByEmail(String email) {
        return loadUserByUsername(email);
    }

    @Override
    @Transactional
    public CreateUserResponse register(CreateUserRequest request) {
        User user = userRepository.save(mapCreateUserRequestToUser(request, authorityService.findByName(Role.USER)));
        return mapUserToUserResponse(user);
    }

    private User mapCreateUserRequestToUser(CreateUserRequest request, Authority authority) {
        return User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .authority(authority)
                .build();
    }

    private CreateUserResponse mapUserToUserResponse(User user) {
        return CreateUserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .build();
    }

}
