package org.scode.pwbox;

/**
 * Indicates PWBox was given encrypted data that seems to be in PWBox format, but a version of the format
 * not supported by the implementation.
 *
 * Note that malicious tampering or arbitrary corruption can trigger this exception.
 */
public class UnsupportedFormatVersionException extends PWBoxException {
    public UnsupportedFormatVersionException() {
    }

    public UnsupportedFormatVersionException(String s) {
        super(s);
    }

    public UnsupportedFormatVersionException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public UnsupportedFormatVersionException(Throwable throwable) {
        super(throwable);
    }
}
