package com.example.mpc.common.response;

import java.util.List;

public class SignatureTaskStatusResponse {
    private String taskId;
    private String groupPublicKey;
    private boolean inProgress;
    private boolean completed;
    private String status;
    private String message;
    private String errorMessage;
    private List<Integer> participants;
    private int receivedGammaCommitments;
    private int receivedMtaResponses;
    private int receivedOffline;
    private int receivedPartialS;

    public SignatureTaskStatusResponse() {
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

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
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

    public int getReceivedGammaCommitments() {
        return receivedGammaCommitments;
    }

    public void setReceivedGammaCommitments(int receivedGammaCommitments) {
        this.receivedGammaCommitments = receivedGammaCommitments;
    }

    public int getReceivedMtaResponses() {
        return receivedMtaResponses;
    }

    public void setReceivedMtaResponses(int receivedMtaResponses) {
        this.receivedMtaResponses = receivedMtaResponses;
    }

    public int getReceivedOffline() {
        return receivedOffline;
    }

    public void setReceivedOffline(int receivedOffline) {
        this.receivedOffline = receivedOffline;
    }

    public int getReceivedPartialS() {
        return receivedPartialS;
    }

    public void setReceivedPartialS(int receivedPartialS) {
        this.receivedPartialS = receivedPartialS;
    }
}
