package com.zura.springSecurity.model;

import jakarta.persistence.*;

@Entity
@Table(name = "userdata")
public class User {
    @Id
    @Column
    @SequenceGenerator(
            name = "id_generator",
            sequenceName = "id_generator",
            allocationSize = 1
    )
    @GeneratedValue (
            strategy = GenerationType.AUTO,
            generator = "id_genrator"
    )
    private Long id;
    @Column
    private String firstName;
    @Column
    private String lastName;
    @Column
    private String email;
    @Column
    private String password;
}
