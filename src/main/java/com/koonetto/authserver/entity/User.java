package com.koonetto.authserver.entity;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String email;

    private String password;

    @ManyToOne
    @JoinColumn(
            name = "authority_id",
            referencedColumnName = "id"
    )
    @Enumerated(EnumType.STRING)
    private Authority authority;
}
