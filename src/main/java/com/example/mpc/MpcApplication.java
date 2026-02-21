package com.example.mpc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MpcApplication {
    private static final Logger logger = LoggerFactory.getLogger(MpcApplication.class);

    public static void main(String[] args) {
        logger.info("Starting MPC application...");
        SpringApplication.run(MpcApplication.class, args);
    }
}