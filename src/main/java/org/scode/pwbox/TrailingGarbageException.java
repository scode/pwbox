package org.scode.pwbox;

public class TrailingGarbageException extends PWBoxException {
    public TrailingGarbageException() {
    }

    public TrailingGarbageException(String s) {
        super(s);
    }

    public TrailingGarbageException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public TrailingGarbageException(Throwable throwable) {
        super(throwable);
    }
}
