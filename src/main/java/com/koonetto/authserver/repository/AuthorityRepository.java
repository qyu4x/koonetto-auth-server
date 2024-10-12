package com.koonetto.authserver.repository;

import com.koonetto.authserver.entity.Authority;
import com.koonetto.authserver.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority, Integer> {
    Optional<Authority> findByName(Role role);
}
