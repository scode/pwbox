package org.scode.pwbox;

public class PWBoxError extends RuntimeException {
    public PWBoxError() {
    }

    public PWBoxError(String s) {
        super(s);
    }

    public PWBoxError(String s, Throwable throwable) {
        super(s, throwable);
    }

    public PWBoxError(Throwable throwable) {
        super(throwable);
    }
}
