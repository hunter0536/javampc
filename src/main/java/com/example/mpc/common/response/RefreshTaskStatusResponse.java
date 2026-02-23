package com.example.mpc.common.response;

import java.util.List;

public class RefreshTaskStatusResponse {
    private String taskId;
    private String groupPublicKey;
    private boolean inProgress;
    private boolean completed;
    private String status;
    private String errorMessage;
    private List<Integer> participants;
    private int receivedR1;
    private int receivedR2;
    private int receivedR3;

    public RefreshTaskStatusResponse() {
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

    public boolean isInProgress() {
        return inProgress;
    }

    public void setInProgress(boolean inProgress) {
        this.inProgress = inProgress;
    }

    public boolean isCompleted() {
        return completed;
    }

    public void setCompleted(boolean completed) {
        this.completed = completed;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public List<Integer> getParticipants() {
        return participants;
    }

    public void setParticipants(List<Integer> participants) {
        this.participants = participants;
    }

    public int getReceivedR1() {
        return receivedR1;
    }

    public void setReceivedR1(int receivedR1) {
        this.receivedR1 = receivedR1;
    }

    public int getReceivedR2() {
        return receivedR2;
    }

    public void setReceivedR2(int receivedR2) {
        this.receivedR2 = receivedR2;
    }

    public int getReceivedR3() {
        return receivedR3;
    }

    public void setReceivedR3(int receivedR3) {
        this.receivedR3 = receivedR3;
    }
}
