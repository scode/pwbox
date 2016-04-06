package org.scode.pwbox.errors;

public class InvalidFormatException extends PWBoxException {
    public InvalidFormatException() {
    }

    public InvalidFormatException(String s) {
        super(s);
    }

    public InvalidFormatException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public InvalidFormatException(Throwable throwable) {
        super(throwable);
    }
}
