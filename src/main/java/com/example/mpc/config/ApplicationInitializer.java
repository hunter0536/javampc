package com.example.mpc.config;

import com.example.mpc.constant.Constants;
import com.example.mpc.service.CGGMPKeyService;
import com.example.mpc.service.DkgService;
import com.example.mpc.service.NodeService;
//import com.example.mpc.service.SignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class ApplicationInitializer implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(ApplicationInitializer.class);

    @Autowired
    private DkgService dkgService;

//    @Autowired
//    private SignatureService signatureService;

    @Autowired
    private CGGMPKeyService cggmpKeyService;

    @Autowired
    private NodeService nodeService;

    @Value("${node.id}")
    private int nodeId;

    @Value("${app.init.cggmp.enabled:true}")
    private boolean enableCggmp;

    @Value("${app.init.legacy.enabled:false}")
    private boolean enableLegacy;

    @Override
    public void run(String... args) throws Exception {
        logger.info("=" .repeat(60));
        logger.info("Initializing application for node {}", nodeId);
        logger.info("=" .repeat(60));

        if (enableCggmp) {
            initializeCggmp();
        } else {
            nodeService.startP2PServer().join();
            logger.info("P2P server started successfully");
        }

        if (enableLegacy) {
            initializeLegacy();
        }

        logger.info("=" .repeat(60));
        logger.info("Application initialization complete for node {}", nodeId);
        logger.info("=" .repeat(60));
    }

    private void initializeCggmp() {
        logger.info("--- Initializing CGGMP services ---");
        try {
            cggmpKeyService.initialize();
            logger.info("Initializing CGGMP signature service...");
            cggmpKeyService.init(Constants.NODES_COUNT).join();
            logger.info("CGGMP services initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize CGGMP services", e);
        }
    }

    private void initializeLegacy() {
        logger.info("--- Initializing legacy services ---");
        try {
            logger.info("Initializing DKG service...");
            dkgService.init().join();
            logger.info("DKG service initialized successfully");

//            logger.info("Initializing Signature service...");
//            signatureService.init(Constants.NODES_COUNT).join();
//            logger.info("Signature service initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize legacy services", e);
        }
    }
}
