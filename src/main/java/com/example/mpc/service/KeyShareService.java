package com.example.mpc.service;

import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.model.KeyShare;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class KeyShareService {
    @Autowired
    private KeyShareDao keyShareDao;

    public KeyShare findByGroupPublicKeySync(int nodeId, String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }
}
