package com.koonetto.authserver.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class WebResponse <T>{

    private T data;

}
