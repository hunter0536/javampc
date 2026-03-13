package com.example.mpc.common.exception;

import org.springframework.http.HttpStatus;

public class MpcException extends RuntimeException {
    private final ErrorCode errorCode;

    public MpcException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public MpcException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public MpcException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public HttpStatus getHttpStatus() {
        return errorCode.getHttpStatus();
    }
}
