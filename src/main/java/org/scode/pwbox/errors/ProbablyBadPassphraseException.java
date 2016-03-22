package org.scode.pwbox.errors;

import org.scode.pwbox.errors.PWBoxException;

/**
 * Thrown to indicate a decryption attempt failed, and the reason is probably that an incorrect passphrase
 * was specified.
 *
 * We say "probably" because any problem is consistent with malicious tampering or arbitrary corruption. Such
 * tampering or corruption may under the right circumstances cause this exception to the thrown.
 *
 * In the event that the file has *not* been tampered with however, and it has not been corrupted, this exception
 * will reliably (barring extremely unlikely collissions in key generation) be thrown rather than a different exception
 * to indicate corruption or tampering.
 *
 * The intent of this exception is to allow a piece of software to give an error message that is much friendly to the
 * user, as the expectation is that almost all failures ever encountered in practice are due to a mis-typed or
 * mis-remembered passphrase.
 */
public class ProbablyBadPassphraseException extends PWBoxException {
    public ProbablyBadPassphraseException() {
    }

    public ProbablyBadPassphraseException(String s) {
        super(s);
    }

    public ProbablyBadPassphraseException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public ProbablyBadPassphraseException(Throwable throwable) {
        super(throwable);
    }
}
