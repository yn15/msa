package com.example.userservice.jpa;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.stereotype.Repository;

@Data
@Entity
@Table(name = "users")
public class UserEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 50, unique = true)
    private String email;
    @Column(nullable = false, length = 50)
    private String name;
    @Column(nullable = false, unique = true)
    private String userId;
    @Column(nullable = false, unique = true)
    private String encryptedPwd;
}
