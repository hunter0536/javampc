package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;

import java.io.Serializable;

public record SignedMessage(NodeService.Message message, String signature, long timestampMs) implements Serializable {
}
