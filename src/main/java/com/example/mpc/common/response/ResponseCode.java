package com.example.mpc.common.response;

public final class ResponseCode {
    private ResponseCode() {
    }

    public static final int SUCCESS = 200;
    public static final int BAD_REQUEST = 400;
    public static final int NOT_FOUND = 404;
    public static final int INTERNAL_ERROR = 500;

    public static final int TASK_NOT_FOUND = 1001;
    public static final int TASK_NOT_COMPLETED = 1002;
    public static final int DKG_IN_PROGRESS = 1003;
    public static final int SIGNATURE_IN_PROGRESS = 1004;
}
