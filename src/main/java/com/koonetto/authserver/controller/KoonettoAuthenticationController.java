package com.koonetto.authserver.controller;

import com.koonetto.authserver.request.CreateUserRequest;
import com.koonetto.authserver.response.CreateUserResponse;
import com.koonetto.authserver.response.WebResponse;
import com.koonetto.authserver.service.KoonettoAuthenticationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class KoonettoAuthenticationController {

    private final KoonettoAuthenticationService koonettoAuthenticationService;

    @PostMapping
    public ResponseEntity<WebResponse<CreateUserResponse>> register(@RequestBody CreateUserRequest createUserRequest) {
        CreateUserResponse userResponse = koonettoAuthenticationService.register(createUserRequest);
        return ResponseEntity.ok(WebResponse.<CreateUserResponse>builder().data(userResponse).build());
    }

//    @PostConstruct
//    public void init() {
//        CreateUserRequest createUserRequest = CreateUserRequest.builder()
//                .email("chocho@gmail.com")
//                .password("chocho")
//                .build();
//        koonettoAuthenticationService.register(createUserRequest);
//    }

}
