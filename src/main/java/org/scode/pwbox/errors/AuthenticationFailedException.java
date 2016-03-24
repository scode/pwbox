package org.scode.pwbox.errors;

import org.scode.pwbox.errors.PWBoxException;

/**
 * Thrown to indicate a decryption attempt failed because of an authention failure. This means one of two things;
 * either the wrong passphrase was provided or the data has been corrupted (e.g. tampered with).
 *
 * It is not possible to determine for certain which is the case.
  */
public class AuthenticationFailedException extends PWBoxException {
    public AuthenticationFailedException() {
    }

    public AuthenticationFailedException(String s) {
        super(s);
    }

    public AuthenticationFailedException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public AuthenticationFailedException(Throwable throwable) {
        super(throwable);
    }
}
