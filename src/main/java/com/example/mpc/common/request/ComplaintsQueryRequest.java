package com.example.mpc.common.request;

public class ComplaintsQueryRequest {
    private String taskId;
    private String reason;
    private String reasonLike;
    private Integer senderId;
    private Integer offenderId;
    private Long fromTs;
    private Long toTs;
    private Integer limit = 50;
    private Integer offset = 0;

    public ComplaintsQueryRequest() {
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getReasonLike() {
        return reasonLike;
    }

    public void setReasonLike(String reasonLike) {
        this.reasonLike = reasonLike;
    }

    public Integer getSenderId() {
        return senderId;
    }

    public void setSenderId(Integer senderId) {
        this.senderId = senderId;
    }

    public Integer getOffenderId() {
        return offenderId;
    }

    public void setOffenderId(Integer offenderId) {
        this.offenderId = offenderId;
    }

    public Long getFromTs() {
        return fromTs;
    }

    public void setFromTs(Long fromTs) {
        this.fromTs = fromTs;
    }

    public Long getToTs() {
        return toTs;
    }

    public void setToTs(Long toTs) {
        this.toTs = toTs;
    }

    public Integer getLimit() {
        return limit;
    }

    public void setLimit(Integer limit) {
        this.limit = limit;
    }

    public Integer getOffset() {
        return offset;
    }

    public void setOffset(Integer offset) {
        this.offset = offset;
    }
}
