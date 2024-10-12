package com.koonetto.authserver.service;

import com.koonetto.authserver.entity.Authority;
import com.koonetto.authserver.entity.Role;

public interface AuthorityService {
    Authority findByName(Role role);
}
