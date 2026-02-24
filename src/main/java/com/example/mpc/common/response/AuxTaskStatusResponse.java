package com.example.mpc.common.response;

public class AuxTaskStatusResponse {
    private String taskId;
    private String status;
    private boolean inProgress;
    private boolean completed;
    private String errorMessage;
    private Object lastErrorEvidence;
    private int receivedCommits;
    private int receivedEcho;
    private int receivedReveal;
    private int receivedProofs;

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

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public Object getLastErrorEvidence() {
        return lastErrorEvidence;
    }

    public void setLastErrorEvidence(Object lastErrorEvidence) {
        this.lastErrorEvidence = lastErrorEvidence;
    }

    public int getReceivedCommits() {
        return receivedCommits;
    }

    public void setReceivedCommits(int receivedCommits) {
        this.receivedCommits = receivedCommits;
    }

    public int getReceivedEcho() {
        return receivedEcho;
    }

    public void setReceivedEcho(int receivedEcho) {
        this.receivedEcho = receivedEcho;
    }

    public int getReceivedReveal() {
        return receivedReveal;
    }

    public void setReceivedReveal(int receivedReveal) {
        this.receivedReveal = receivedReveal;
    }

    public int getReceivedProofs() {
        return receivedProofs;
    }

    public void setReceivedProofs(int receivedProofs) {
        this.receivedProofs = receivedProofs;
    }
}
