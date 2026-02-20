package com.example.mpc;

import com.example.mpc.service.DkgService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MpcApplication implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(MpcApplication.class);
    
    @Autowired
    private DkgService dkgService;
    
    @Value("${node.id}")
    private int nodeId;

    public static void main(String[] args) {
        SpringApplication.run(MpcApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info("Initializing DKG service for node {}...", nodeId);
        dkgService.init().join();
        logger.info("DKG service initialized successfully for node {}", nodeId);
    }
}