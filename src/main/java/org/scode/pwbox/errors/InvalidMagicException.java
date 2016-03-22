package org.scode.pwbox.errors;

/**
 * Indicates PWBox was passed encrypted data that does not seem to be in PWBox format.
 *
 * Note that malicious tampering or random corruption can trigger this exception.
 */
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
