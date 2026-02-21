package com.example.mpc;

import com.example.mpc.constant.Constants;
import com.example.mpc.service.DkgService;
import com.example.mpc.service.SignatureService;
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
    
    @Autowired
    private SignatureService signatureService;
    
    @Value("${node.id}")
    private int nodeId;
    
    // 使用Constants中的常量
    private final int nodesCount = Constants.NODES_COUNT;

    public static void main(String[] args) {
        SpringApplication.run(MpcApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info("Initializing services for node {}...", nodeId);
        
        // 初始化DKG服务
        logger.info("Initializing DKG service...");
        dkgService.init().join();
        logger.info("DKG service initialized successfully");
        
        // 初始化签名服务
        logger.info("Initializing Signature service...");
        signatureService.init(nodesCount).join();
        logger.info("Signature service initialized successfully");
        
        logger.info("All services initialized successfully for node {}", nodeId);
    }
}