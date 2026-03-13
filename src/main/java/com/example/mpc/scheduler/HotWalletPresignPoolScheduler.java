package com.example.mpc.scheduler;

import com.example.mpc.common.annotation.SchedulerComponent;
import com.example.mpc.service.HotWalletPresignPoolService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
@SchedulerComponent
public class HotWalletPresignPoolScheduler {

    @Autowired
    private HotWalletPresignPoolService presignPoolService;

    @Scheduled(fixedDelayString = "${cggmp.presign.pool.refreshIntervalMs:30000}")
    public void scheduledHotWalletPresignPoolRefresh() {
        presignPoolService.scheduledRefresh();
    }
}
