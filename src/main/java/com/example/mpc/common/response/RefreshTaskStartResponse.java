package com.example.mpc.common.response;

public class RefreshTaskStartResponse {
    private String taskId;
    private String groupPublicKey;
    private String status;

    public RefreshTaskStartResponse() {
    }

    public RefreshTaskStartResponse(String taskId, String groupPublicKey, String status) {
        this.taskId = taskId;
        this.groupPublicKey = groupPublicKey;
        this.status = status;
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public void setGroupPublicKey(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
