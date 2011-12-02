package org.scode.pwbox;

/**
 * Indicates the encrypted text given to PWBox for decryption was truncated (i.e., there was missing data
 * at the end).
 *
 * Note that malicious tampering or arbitrary corruption can trigger this exception.
 */
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
