package com.example.mpc.controller;

import com.example.mpc.service.NodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/node")
public class NodeController {
    @Autowired
    private NodeService nodeService;

    @GetMapping("/state")
    public Map<String, Object> getState() {
        Map<String, Object> state = new HashMap<>();
        state.put("nodeCount", nodeService.getNodes().size());
        state.put("nodes", nodeService.getNodesSnapshot());
        state.put("networkReady", nodeService.isNetworkReady());
        return state;
    }
}
