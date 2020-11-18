package com.rh.cloudhsm;

public class CloudHsmException extends RuntimeException {
    public CloudHsmException(){

    }

    public CloudHsmException(String message) { super(message); }

    public CloudHsmException(String message, Throwable cause) {
        super(message, cause);
    }

    public CloudHsmException(Throwable cause) {
        super(cause);
    }

    public CloudHsmException(String message, Throwable cause, boolean enableSuppression,
                             boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
