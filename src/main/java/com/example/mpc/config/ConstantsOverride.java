package com.example.mpc.config;

import com.example.mpc.constant.Constants;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ConstantsOverride {
    @Value("${mpc.nodeDiscoveryIntervalMs:5000}")
    private long nodeDiscoveryIntervalMs;

    @Value("${mpc.dkg.commitmentTimeoutSeconds:180}")
    private long dkgCommitmentTimeoutSeconds;

    @Value("${mpc.dkg.shareTimeoutSeconds:180}")
    private long dkgShareTimeoutSeconds;

    @Value("${mpc.dkg.roundTimeoutSeconds:180}")
    private long dkgRoundTimeoutSeconds;

    @Value("${mpc.dkg.taskTimeoutMs:300000}")
    private long dkgTaskTimeoutMs;

    @Value("${mpc.dkg.broadcastRetryCount:3}")
    private int dkgBroadcastRetryCount;

    @Value("${mpc.dkg.broadcastRetryIntervalMs:1000}")
    private long dkgBroadcastRetryIntervalMs;

    @Value("${mpc.dkg.initWaitMs:2000}")
    private long dkgInitWaitMs;

    @PostConstruct
    public void apply() {
        Constants.NODE_DISCOVERY_INTERVAL_MS = nodeDiscoveryIntervalMs;
        Constants.DKG_COMMITMENT_TIMEOUT_SECONDS = dkgCommitmentTimeoutSeconds;
        Constants.DKG_SHARE_TIMEOUT_SECONDS = dkgShareTimeoutSeconds;
        Constants.DKG_ROUND_TIMEOUT_SECONDS = dkgRoundTimeoutSeconds;
        Constants.DKG_TASK_TIMEOUT_MS = dkgTaskTimeoutMs;
        Constants.DKG_BROADCAST_RETRY_COUNT = dkgBroadcastRetryCount;
        Constants.DKG_BROADCAST_RETRY_INTERVAL_MS = dkgBroadcastRetryIntervalMs;
        Constants.DKG_INIT_WAIT_MS = dkgInitWaitMs;
    }
}
