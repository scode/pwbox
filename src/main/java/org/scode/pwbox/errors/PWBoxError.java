package org.scode.pwbox.errors;

/**
 * Common base class for PWBox specific errors that indicate an internal bug in PWBox or a dependent library.
 */
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
