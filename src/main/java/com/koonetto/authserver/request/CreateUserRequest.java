package com.koonetto.authserver.request;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserRequest {

    private String email;

    private String password;


}
