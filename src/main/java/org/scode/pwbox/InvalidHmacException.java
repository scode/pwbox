package org.scode.pwbox;

public class InvalidHmacException extends PWBoxException {
    public InvalidHmacException() {
    }

    public InvalidHmacException(String s) {
        super(s);
    }

    public InvalidHmacException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public InvalidHmacException(Throwable throwable) {
        super(throwable);
    }
}
