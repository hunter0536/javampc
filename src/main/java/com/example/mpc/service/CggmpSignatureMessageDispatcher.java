package com.example.mpc.service;

import com.example.mpc.common.util.ThreadPoolUtil;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

final class CggmpSignatureMessageDispatcher {
    private final CggmpSignatureService svc;

    CggmpSignatureMessageDispatcher(CggmpSignatureService svc) {
        this.svc = svc;
    }

    CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return svc.handleMessage(senderId, message);
    }
}
