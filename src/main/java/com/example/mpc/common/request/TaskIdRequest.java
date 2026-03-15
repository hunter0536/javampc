package com.example.mpc.common.request;

public class TaskIdRequest {
    private String taskId;

    public TaskIdRequest() {
    }

    public TaskIdRequest(String taskId) {
        this.taskId = taskId;
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }
}
