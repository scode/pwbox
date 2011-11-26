package org.scode.pwbox;

public class TruncatedException extends PWBoxException {
    public TruncatedException() {
    }

    public TruncatedException(String s) {
        super(s);
    }

    public TruncatedException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public TruncatedException(Throwable throwable) {
        super(throwable);
    }
}
