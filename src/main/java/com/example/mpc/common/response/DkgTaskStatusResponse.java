package com.example.mpc.common.response;

public class DkgTaskStatusResponse {
    private String taskId;
    private String status;
    private boolean inProgress;
    private boolean completed;
    private String groupPublicKey;
    private String errorMessage;
    private int receivedCommitments;
    private int receivedShares;
    private int receivedRound1;
    private int receivedRound2;

    public DkgTaskStatusResponse() {
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
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

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public void setGroupPublicKey(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public int getReceivedCommitments() {
        return receivedCommitments;
    }

    public void setReceivedCommitments(int receivedCommitments) {
        this.receivedCommitments = receivedCommitments;
    }

    public int getReceivedShares() {
        return receivedShares;
    }

    public void setReceivedShares(int receivedShares) {
        this.receivedShares = receivedShares;
    }

    public int getReceivedRound1() {
        return receivedRound1;
    }

    public void setReceivedRound1(int receivedRound1) {
        this.receivedRound1 = receivedRound1;
    }

    public int getReceivedRound2() {
        return receivedRound2;
    }

    public void setReceivedRound2(int receivedRound2) {
        this.receivedRound2 = receivedRound2;
    }
}
