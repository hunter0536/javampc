package com.example.mpc.config;

import com.example.mpc.constant.Constants;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.CggmpDkgService;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.DatabaseService;
import com.example.mpc.service.GennaroDkgService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.SimpleSignatureService;
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
    private DatabaseService databaseService;

    @Autowired
    private GennaroDkgService gennaroDkgService;


    @Autowired
    private CggmpSignatureService cggmpSignatureService;

    @Autowired
    private CggmpAuxService cggmpAuxService;

    @Autowired
    private CggmpDkgService cggmpDkgService;

    @Autowired
    private SimpleSignatureService simpleSignatureService;

    @Autowired
    private NodeService nodeService;

    @Value("${node.id}")
    private int nodeId;

    @Value("${app.init.cggmp.enabled:true}")
    private boolean enableCggmp;

    @Value("${app.init.legacy.enabled:true}")
    private boolean enableLegacy;

    @Override
    public void run(String... args) throws Exception {
        logger.info("=".repeat(60));
        logger.info("Initializing application for node {}", nodeId);
        logger.info("=".repeat(60));

        initializeDatabase();

        if (enableCggmp) {
            initializeCggmp();
        } else {
            nodeService.startP2PServer()
                    .thenRun(() -> logger.info("P2P server started successfully"))
                    .exceptionally(ex -> {
                        logger.error("Failed to start P2P server", ex);
                        return null;
                    });
        }

        if (enableLegacy) {
            initializeLegacy();
        }

        logger.info("=".repeat(60));
        logger.info("Application initialization complete for node {}", nodeId);
        logger.info("=".repeat(60));
    }

    private void initializeCggmp() {
        logger.info("--- Initializing CGGMP services ---");
        try {
            cggmpSignatureService.initialize();
            cggmpAuxService.init(Constants.NODES_COUNT)
                    .thenRun(() -> {
                        logger.info("Initializing CGGMP DKG service...");
                        cggmpDkgService.init(Constants.NODES_COUNT)
                                .thenRun(() -> logger.info("CGGMP DKG service initialized successfully"))
                                .exceptionally(ex -> {
                                    logger.error("Failed to initialize CGGMP DKG service", ex);
                                    return null;
                                });
                        logger.info("Initializing CGGMP signature service...");
                        cggmpSignatureService.init(Constants.NODES_COUNT)
                                .thenRun(() -> {
                                    cggmpAuxService.ensureAuxProvisionedAfterNetworkReady();
                                    logger.info("CGGMP services initialized successfully");
                                })
                                .exceptionally(ex -> {
                                    logger.error("Failed to initialize CGGMP signature service", ex);
                                    return null;
                                });
                    })
                    .exceptionally(ex -> {
                        logger.error("Failed to initialize CGGMP AUX service", ex);
                        return null;
                    });
        } catch (Exception e) {
            logger.error("Failed to initialize CGGMP services", e);
        }
    }

    private void initializeDatabase() {
        logger.info("--- Initializing database ---");
        try {
            databaseService.initShareDatabase(nodeId);
            logger.info("Database initialized successfully for node {}", nodeId);
        } catch (Exception e) {
            logger.error("Failed to initialize database: {}", e.getMessage(), e);
        }
    }

    private void initializeLegacy() {
        logger.info("--- Initializing legacy services ---");
        try {
            logger.info("Initializing Simple signature service...");
            simpleSignatureService.init()
                    .thenRun(() -> logger.info("Simple signature service initialized successfully"))
                    .exceptionally(ex -> {
                        logger.error("Failed to initialize Simple signature service", ex);
                        return null;
                    });

            logger.info("Initializing Gennaro DKG service...");
            gennaroDkgService.init()
                    .thenRun(() -> logger.info("Gennaro DKG service initialized successfully"))
                    .exceptionally(ex -> {
                        logger.error("Failed to initialize Gennaro DKG service", ex);
                        return null;
                    });

        } catch (Exception e) {
            logger.error("Failed to initialize legacy services", e);
        }
    }
}
