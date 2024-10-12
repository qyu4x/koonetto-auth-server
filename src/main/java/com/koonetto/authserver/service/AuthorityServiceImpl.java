package com.koonetto.authserver.service;

import com.koonetto.authserver.entity.Authority;
import com.koonetto.authserver.entity.Role;
import com.koonetto.authserver.repository.AuthorityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuthorityServiceImpl implements AuthorityService{

    private final AuthorityRepository authorityRepository;

    @Override
    @Cacheable(value = "products", key = "#role.name()")
    public Authority findByName(Role role) {
        return authorityRepository.findByName(Role.USER)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Error accours"));
    }
}
