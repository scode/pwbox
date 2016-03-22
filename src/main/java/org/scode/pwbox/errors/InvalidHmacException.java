package org.scode.pwbox.errors;

/**
 * Indicates that PWBox was passed data which did not pass cryptographic integrity checking.
 *
 * This is intended to convey that the data has been corrupted or tampered with.
 */
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
