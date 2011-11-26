package org.scode.pwbox;

public class InvalidMagicException extends PWBoxException {
    public InvalidMagicException() {
    }

    public InvalidMagicException(String s) {
        super(s);
    }

    public InvalidMagicException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public InvalidMagicException(Throwable throwable) {
        super(throwable);
    }
}
