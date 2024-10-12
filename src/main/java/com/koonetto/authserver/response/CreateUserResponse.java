package com.koonetto.authserver.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateUserResponse {

    private Integer id;

    private String email;

}
