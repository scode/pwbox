package org.scode.pwbox;

/**
 * Indicates PWBox was successfully able to interpret an encrypted text, but there was left-over trailing
 * garbage at the end.
 *
 * Note that malicious tampering or arbitrary corruption can trigger this exception.
 */
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
