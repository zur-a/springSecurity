package com.zura.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/demo")
public class DemoController {
    @GetMapping
    public ResponseEntity<String> securedEndpoint() {
        return ResponseEntity.ok("Secured endpoint");
    }
}
