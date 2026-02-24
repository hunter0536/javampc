package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;

import java.io.Serializable;

public class SignedMessage implements Serializable {
    public final NodeService.Message message;
    public final String signature;
    public final long timestampMs;

    public SignedMessage(NodeService.Message message, String signature, long timestampMs) {
        this.message = message;
        this.signature = signature;
        this.timestampMs = timestampMs;
    }
}
