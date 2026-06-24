package com.platform.authserver.token;

public class ReuseDetectedException extends RuntimeException {
    public ReuseDetectedException(String message) {
        super(message);
    }
}
