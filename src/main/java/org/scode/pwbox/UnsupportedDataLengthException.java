package org.scode.pwbox;

public class UnsupportedDataLengthException extends PWBoxException {
    public UnsupportedDataLengthException() {
    }

    public UnsupportedDataLengthException(String s) {
        super(s);
    }

    public UnsupportedDataLengthException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public UnsupportedDataLengthException(Throwable throwable) {
        super(throwable);
    }
}
