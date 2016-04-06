package org.scode.pwbox;

import org.scode.pwbox.errors.AuthenticationFailedException;
import org.scode.pwbox.errors.InvalidMagicException;
import org.scode.pwbox.errors.PWBoxError;
import org.scode.pwbox.errors.PWBoxException;
import org.scode.pwbox.errors.TrailingGarbageException;
import org.scode.pwbox.errors.TruncatedException;
import org.scode.pwbox.errors.UnsupportedDataLengthException;
import org.scode.pwbox.errors.UnsupportedVersionException;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Introduction
 * ============
 *
 * We try to do one thing, and make it simple: Take a reasonably small (fits in memory, quick to encrypt/decrypt)
 * amount of data, and allow encryption and decryption based on the use of a passphrase. The target usage is
 * that of password vaults and similar smaller pieces of meta data that is sometimes useful and typically painful
 * unless you're a crypto guy.
 *
 * We do *not* attempt to protect against local attacks. For example, there is no memory locking to prevent
 * a passphrase from ending up in swap; the JVM might core dump and include a passphrase in the resulting
 * dump, etc. The purpose here is only to provide a mechanism to produce a tamper resistant encrypted blob of data
 * that can be transferred elsewhere, such as remote untrusted storage for backups.
 *
 * Truncation detection
 * ====================
 *
 * As is apparent in the wire format section, we have some bits reserved for truncation detection. This information
 * is not HMAC:ed, and not "trusted". It is merely there to assist the user in the somewhat likely cause of a file
 * containing a PW box being truncated. Rather than just reporting some kind of corruption, we intend on nicely telling
 * the user that it is likely "just" truncated'.
 *
 * Wire format
 * ===========
 *
 * The format of encrypted data is as follows:
 *
 *
 *     The string "pwbox: this data is pwbox encrypted\n" in ASCII.
 *     1, indicating the first version of the PWBox format
 *     16 byte IV used for encrypting user provided text (TODO: appropriate IV size with GCM?)
 *     32 byte salt used to generate the key used to encrypt the user provided text
 *     8 bytes in DataOutputStream.writeLong() format of length of the remainder (for
 *       truncation detection for user-friendly errors, not HMAC:ed).
 *     Remainder: Encrypted text (AES/GCM/NoPadding)
 *
 */
public class PWBox1Impl {
    /**
     * Header that should appear at the beginning of pwbox encrypted data.
     */
    private static final String PWBOX_HEADER = "pwbox: this data is pwbox encrypted\n";

    /** Visible for testing.
     *
     * I know of no reason to skimp on the salt length, and 32 bytes is firmly above what seems to be the
     * norm.
     */
    static final int SALT_LENGTH_IN_BYTES = 32;

    /**
     * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf indicates that there is
     * no upper bound or specific length required or expected:
     *
     *    "Another useful property is that it accepts initialization vectors of arbitrary length, which makes it
     *     easier for applications to meet the requirement that all IVs be distinct. In many situations in which
     *     authenticated encryption is needed, there is a data element that could be used as a nonce, or as a
     *     part of a nonce, except that the length of the element(s) may exceed the block size of the cipher. In
     *     GCM, a nonce of any size can be used as the IV."
     *
     * https://tools.ietf.org/html/rfc5288 uses a nonce length of 12. I've found some conflicting statements,
     * but no indication that larger isn't safe except possibly because there exist implementations that require
     * 12 bytes (so there might be a compatibility concern).
     *
     * 64 bytes (512 bits) seemed like a safe choice.
     */
    private static final int IV_LENGTH_IN_BYTES = 64;

    /**
     * The assumption of PWBox is that small amounts of data are being encrypted and decrypted, meaning that
     * the performance penalty of a larger key is irrelevant. Ordinarily there would be no reason not to go for
     * a 256 bit key here. However, it appears that depending on the environment, 256 bit keys may fail with
     * InvalidKeyExceptions. Possibly due to:
     *
     *   http://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size
     *
     * We reluctantly stick to 128 bits as a result in order to minimize the chance of leaving useres in a
     * lurch.
     */
    private static final int KEY_LENGTH_IN_BITS = 128;

    /**
     * Key stretching iteration count. The higher the more resilience you get against bruce force attacks against
     * a poor passphrase.
     *
     * 10000 yields about 500 encryptions per second (see keyStretchingPerfTest) on a 2016 macbook pro.
     */
    private static final int PBE_ITERATION_COUNT = 10000;

    /**
     * AES was chosen since it seems to be the currently preferred default choice. As a non-cryptographer, I see
     * no reason to choose something else without a specific reason to.
     */
    private static final String ENCRYPTION_ALGORITHM = "AES";

    /**
     * GCM mode provides authentication and encryption both, without us having to separately HMAC the encrypted
     * text.
     *
     *   https://en.wikipedia.org/wiki/Galois/Counter_Mode
     */
    private static final String CIPHER_SPEC = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * See http://en.wikipedia.org/wiki/PBKDF2 about PBKDF2. bcrypt and scrypt are supposed to be better, but I
     * went with PBKDF2 because it's very established and because it's available by default in the JDK.
     */
    private static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA512";

    /** Visible for testing. */
    Key generateKey(final String passphrase, final byte[] salt) {
        final SecretKeyFactory f;
        try {
            f = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
            final PBEKeySpec ks = new PBEKeySpec(passphrase.toCharArray(), salt, PBE_ITERATION_COUNT, KEY_LENGTH_IN_BITS);
            final SecretKey k;
            try {
                k = f.generateSecret(ks);
            } finally {
                // Avoid keeping the user's passphrase around longer than necessary. This is a "we might as well" and
                // should never be relied upon as there is no guarantee provided (e.g. copying GC, we might have been
                // paged to disk, etc). We do not attempt or advertise resillience against local attacks.
                ks.clearPassword();
            }
            return new SecretKeySpec(k.getEncoded(), ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException
                |InvalidKeySpecException e) {
            throw new PWBoxError(e);
        }
    }

    /** Visible for testing. */
    byte[] generateSalt() {
        final SecureRandom sr = new SecureRandom();

        final byte[] salt = new byte[SALT_LENGTH_IN_BYTES];
        sr.nextBytes(salt);

        return salt;
    }

    /** Visible for testing. */
    byte[] generateIv() {
        final SecureRandom sr = new SecureRandom();

        final byte[] iv = new byte[IV_LENGTH_IN_BYTES];
        sr.nextBytes(iv);

        return iv;
    }

    /** Visible for testing. */
    byte[] encrypt(final Key k, final byte[] iv, final byte[] plainText) {
        final Cipher c;
        try {
            c = Cipher.getInstance(CIPHER_SPEC);
            c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return c.doFinal(plainText);
        } catch (NoSuchAlgorithmException
                |NoSuchPaddingException
                |IllegalBlockSizeException
                |BadPaddingException
                |InvalidKeyException
                |InvalidAlgorithmParameterException e) {
            throw new PWBoxError(e);
        }
    }

    /** Visible for testing. */
    byte[] decrypt(final Key k, final byte[] iv, final byte[] encryptedText) throws AuthenticationFailedException {
        try {
            final Cipher c = Cipher.getInstance(CIPHER_SPEC);
            c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return c.doFinal(encryptedText);
        } catch (AEADBadTagException e) {
            throw new AuthenticationFailedException(e);
        } catch (IllegalBlockSizeException
                |InvalidKeyException
                |BadPaddingException
                |NoSuchAlgorithmException
                |NoSuchPaddingException
                |InvalidAlgorithmParameterException e) {
            throw new PWBoxError(e);
        }
    }

    public byte[] encrypt(final String passphrase, final byte[] plaintext) throws PWBoxException, PWBoxError {
        try {
            // Prepare byte arrays of content in the same order as documented in the class docs, and
            // in the same order as the resulting bytes.
            final byte[] magic = PWBOX_HEADER.getBytes("ASCII");

            final byte[] version = new byte[1];
            version[0] = 1;

            final byte[] userEncIv = this.generateIv();
            final byte[] userKeySalt = this.generateSalt();

            final Key userEncKey = this.generateKey(passphrase, userKeySalt);

            final byte[] encUserText = this.encrypt(userEncKey, userEncIv, plaintext);

            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            final DataOutputStream dout = new DataOutputStream(bout);
            dout.write(magic);
            dout.write(version);
            dout.write(userEncIv);
            dout.write(userKeySalt);
            dout.writeLong(encUserText.length);
            dout.write(encUserText);

            final byte[] encrypted = bout.toByteArray();

            // For pure paranoia. We are not concerned with performance given our premises.
            final byte[] decrypted = this.decrypt(passphrase, encrypted);
            if (!Arrays.equals(decrypted, plaintext)) {
                throw new PWBoxError("bug: decrypting what we just encrypted did not yield matching plaintext");
            }

            return encrypted;
        } catch (IOException e) {
            throw new PWBoxError(e);
        }
    }

    public byte[] decrypt(final String passphrase, final byte[] encryptedContent) throws PWBoxException, PWBoxError {
        try {
            final DataInputStream din = new DataInputStream(new ByteArrayInputStream(encryptedContent));

            final byte[] magic = PWBOX_HEADER.getBytes("ASCII");
            try {
                final byte[] rmagic = new byte[magic.length];
                din.readFully(rmagic);
                if (!Arrays.equals(magic, rmagic)) {
                    throw new InvalidMagicException("invalid magic - not PWBox data?");
                }
            } catch (EOFException e) {
                throw new InvalidMagicException("input data did not contain magic indicating it is PWBox data - too short");
            }

            final byte[] rversion = new byte[1];
            try {
                din.readFully(rversion);
                if (rversion[0] != 1) {
                    throw new UnsupportedVersionException("only support version 1, got version " + rversion[0]);
                }
            } catch (EOFException e) {
                throw new TruncatedException("truncated before format version could be read");
            }

            final byte[] userEncIv = new byte[IV_LENGTH_IN_BYTES];
            final byte[] userKeySalt = new byte[SALT_LENGTH_IN_BYTES];

            try {
                din.readFully(userEncIv);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encryption iv");
            }

            try {
                din.readFully(userKeySalt);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encryption salt");
            }

            long len;
            try {
                len = din.readLong();
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading length");
            }

            if (len > Integer.MAX_VALUE) {
                throw new UnsupportedDataLengthException("length > Integer.MAX_VALUE");
            }

            if (len < 0) {
                throw new UnsupportedDataLengthException("length < 0");
            }

            final byte[] encUserText = new byte[(int)len];
            try {
                din.readFully(encUserText);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encrypted text (expected " + len + " bytes after header)");
            }

            if (din.available() != 0) {
                throw new TrailingGarbageException("expected EOF after reading " + len + " bytes of encrypted text (after header)");
            }

            final Key userKey = this.generateKey(passphrase, userKeySalt);

            return this.decrypt(userKey, userEncIv, encUserText);
        } catch (IOException e) {
            throw new PWBoxError(e);
        }
    }
}
