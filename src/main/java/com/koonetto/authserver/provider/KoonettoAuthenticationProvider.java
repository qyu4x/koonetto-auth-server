package com.koonetto.authserver.provider;

import com.koonetto.authserver.service.KoonettoAuthenticationService;
import com.koonetto.authserver.service.KoonettoAuthenticationServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class KoonettoAuthenticationProvider implements AuthenticationProvider {


    private final PasswordEncoder passwordEncoder;

    private final KoonettoAuthenticationService koonettoAuthenticationService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails userDetails = koonettoAuthenticationService.loadUserByEmail(email);
        if (passwordEncoder.matches(password, userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), password, userDetails.getAuthorities());
        } else {
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
