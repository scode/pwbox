package org.scode.pwbox;

/**
 * Indicates PWBox was given encrypted data that seems to be in PWBox format, but a version of the format
 * not supported by the implementation. This is intended to convey that data has been encrypted with a
 * newer version of the code than is trying to decrypt it.
 *
 * Note that malicious tampering or arbitrary corruption can trigger this exception.
 */
public class UnsupportedVersionException extends PWBoxException {
    public UnsupportedVersionException() {
    }

    public UnsupportedVersionException(String s) {
        super(s);
    }

    public UnsupportedVersionException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public UnsupportedVersionException(Throwable throwable) {
        super(throwable);
    }
}
