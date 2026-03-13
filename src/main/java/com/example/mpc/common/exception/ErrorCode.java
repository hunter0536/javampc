package com.example.mpc.common.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    NO_AUX_DATA_AVAILABLE("No AUX data available. Please run AUX provisioning first.", HttpStatus.BAD_REQUEST, "AUX001"),
    TASK_NOT_FOUND("Task not found", HttpStatus.NOT_FOUND, "TASK001"),
    TASK_ALREADY_COMPLETED("Task already completed", HttpStatus.BAD_REQUEST, "TASK002"),
    INVALID_GROUP_PUBLIC_KEY("Invalid group public key", HttpStatus.BAD_REQUEST, "KEY001"),
    INVALID_MESSAGE("Invalid message", HttpStatus.BAD_REQUEST, "MSG001"),
    AUX_TASK_ALREADY_EXISTS("AUX task already exists", HttpStatus.BAD_REQUEST, "AUX002"),
    HOT_WALLET_ALREADY_EXISTS("Hot wallet already exists", HttpStatus.BAD_REQUEST, "HOT001"),
    PRESIGN_POOL_EMPTY("Presign pool is empty", HttpStatus.SERVICE_UNAVAILABLE, "PRESIGN001"),
    TASK_FAILED("Task failed", HttpStatus.INTERNAL_SERVER_ERROR, "TASK999");

    private final String message;
    private final HttpStatus httpStatus;
    private final String code;

    ErrorCode(String message, HttpStatus httpStatus, String code) {
        this.message = message;
        this.httpStatus = httpStatus;
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getCode() {
        return code;
    }
}
