package org.scode.pwbox;

/**
 * Common base class for all exceptions that indicate a problem that is not an internal bug; thus, they are
 * checked.
 */
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
