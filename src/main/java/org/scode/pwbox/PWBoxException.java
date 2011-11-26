package org.scode.pwbox;

public class PWBoxException extends Exception {
    public PWBoxException() {
    }

    public PWBoxException(String s) {
        super(s);
    }

    public PWBoxException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public PWBoxException(Throwable throwable) {
        super(throwable);
    }
}
