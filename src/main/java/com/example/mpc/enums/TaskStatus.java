package com.example.mpc.enums;

public enum TaskStatus {
    PENDING("pending"),
    IN_PROGRESS("in_progress"),
    ROUND1_WAITING("round1_waiting"),
    ROUND2_WAITING("round2_waiting"),
    VALIDATING("validating"),
    COMPLETING("completing"),
    COMPLETED("completed"),
    FAILED("failed"),
    TIMEOUT("timeout");

    private final String value;

    TaskStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    public boolean isFinished() {
        return this == COMPLETED || this == FAILED || this == TIMEOUT;
    }

    public boolean isRunning() {
        return this == IN_PROGRESS || this == ROUND1_WAITING || 
               this == ROUND2_WAITING || this == VALIDATING || this == COMPLETING;
    }
}
