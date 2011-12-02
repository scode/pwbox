package org.scode.pwbox;

/**
 * Indicates PWBox was passed data which may (but need not) be correctly formatted, but the length of the
 * data was longer than that supported by the implementation.
 *
 * For the intended use-case this should never be a problem as we support data sizes up to what fits in a
 * Java int. The API is not expected or intended to be practical for data sizes that even approach that.
 *
 * Note that malicious tampering or arbitrary corruption can trigger this exception.
 */
public class UnsupportedDataLengthException extends PWBoxException {
    public UnsupportedDataLengthException() {
    }

    public UnsupportedDataLengthException(String s) {
        super(s);
    }

    public UnsupportedDataLengthException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public UnsupportedDataLengthException(Throwable throwable) {
        super(throwable);
    }
}
