package org.scode.pwbox;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
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
 * Passphrase marker
 * =================
 *
 * In order to be user friendly, we wish to differentiate decryption failures resulting from an incorrect
 * passphrase from other decryption failures.
 *
 * The strategy implement here is to encrypt a static known string - the "passphrase marker".
 *
 * If we can successfully decrypt said marker and the plain text matches, we presume that the chosen passphrase
 * is correct and proceed to attempt decryption of the user provided text.
 *
 * The passphrase marker is encrypted using a different IV than the user provided text.
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
 * <pre>
 *     Byte 00:      'P' ASCII code
 *     Byte 01:      'W" ASCII code
 *     Byte 02:      'B' ASCII code
 *     Byte 03:      'o' ASCII code
 *     Byte 04:      'x' ASCII code
 *     Byte 05:      1, indicating the first version of the PWBox format
 *     Byte 06-21:   16 byte IV used for encrypting the passphrase marker
 *     Byte 22-37:   16 byte IV used for encrypting user provided text
 *     Byte 38-69:   32 byte salt used to generate the key used to encrypt the passphrase marker
 *     Byte 70-101:  32 byte salt used to generate the key used to encrypt the user provided text
 *     Byte 102-133: 32 byte salt used for HMAC key
 *     Byte 134-153: 20 bytes HMAC (SHA1) over iv + encryption key + encrypted text
 *     Byte 154-201: 48 byte encrypted passphrase marker
 *     Byte 202-209: 8 bytes in DataOutputStream.writeLong() format of length of the remainder (for
 *                   truncation detection for user-friendly errors, not HMAC:ed).
 *     Byte 210-EOF: Encrypted text (AES/CBC/PKCS5PADDING)
 * </pre>
 *
 */
public class PWBox1Impl {
    /** Visible for testing.
     *
     * I chose salt length to be equal to key length on the hypothesis that a salt length larger than the key size
     * is useless, and I know of no reason to prefer a smaller one.
     */
    static final int SALT_LENGTH_IN_BYTES = 32;

    /**
     * The IV length must be 16 bytes long according to an InvalidAlgorithmParameterException which is otherwise
     * thrown by the AESCipher (tested on JDK 1.6 on MacOS). I am unfamiliar with the implications cryptographically.
     */
    private static final int IV_LENGTH_IN_BYTES = 16;

    /**
     * The assumption of PWBox is that small amounts of data are being encrypted and decrypted, meaning that
     * the performance penalty of a larger key is irrelevant. So, go with 256 bits (instead of 128).
     *
     * TODO(scode): Temporarily set to 128 because 256 generates "illegal key size" on my system, possibly
     *              due to http://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size
     */
    private static final int KEY_LENGTH_IN_BITS = 128;

    /**
     * Key stretching iteration count. The higher the more resilience you get against bruce force attacks against
     * a poor passphrase. I chose 10000 based on ad-hoc performance measurements on my MacBook. Essentially, "unit
     * tests still run reasonably fast, so it's okay for the end-user that only needs to wait for a handful of
     * key generations".
     */
    private static final int PBE_ITERATION_COUNT = 10000;

    /**
     * The known plaintext which is used to give a friendlier indication that the wrong passphrase was probably
     * used.
     */
    private static final String CORRECT_PASSPHRASE_MARKER = "it appears that the passphrase is correct";

    /**
     * The length of CORRECT_PASSPHRASE_MARKER when encrypted with our choice of keys and algorithms. Empirically
     * observed and hard-coded.
     */
    private static final int CORRECT_PASSPHRASE_MARKER_CRYPTED_LENGTH = 48;

    /**
     * AES was chosen since it seems to be the currently preferred default choice. As a non-cryptographer, I see
     * no reason to choose something else without a specific reason to.
     */
    private static final String ENCRYPTION_ALGORITHM = "AES";

    /**
     * CBC and CTR seem to be commonly preferred modes, and I did not want to diverge from commonly accepted
     * defaults. One reason to choose CTR is the fact that it allows parallel encryption/decryption, but as the
     * premise of this library is that small amounts of data are dealt with we do not care about that. Feedback
     * I got indicated that CBC would degrade better in case of a low-entropy IV, so I stayed with that.
     */
    private static final String CIPHER_SPEC = "AES/CBC/PKCS5PADDING";

    /**
     * See http://en.wikipedia.org/wiki/PBKDF2 about PBKDF2. bcrypt and scrypt are supposed to be better, but I
     * went with PBKDF2 because it's very established and because it's available by default in the JDK. Availability
     * in the JDK goes for SHA1 too.
     */
    private static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA1";

    /**
     * SHA1 due to availability of HmacSHA1 in JDK.
     */
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    /** Visible for testing. */
    Key generateKey(String passphrase, byte[] salt) {
        final SecretKeyFactory f;
        try {
            f = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
            final KeySpec ks = new PBEKeySpec(passphrase.toCharArray(), salt, PBE_ITERATION_COUNT, KEY_LENGTH_IN_BITS);
            final SecretKey s = f.generateSecret(ks);
            return new SecretKeySpec(s.getEncoded(), ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new PWBoxError(e);
        } catch (InvalidKeySpecException e) {
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
    byte[] encrypt(Key k, byte[] iv, byte[] plainText) {
        final Cipher c;
        try {
            c = Cipher.getInstance(CIPHER_SPEC);
            c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
            return c.doFinal(plainText);
        } catch (NoSuchAlgorithmException e) {
            throw new PWBoxError(e);
        } catch (NoSuchPaddingException e) {
            throw new PWBoxError(e);
        } catch (IllegalBlockSizeException e) {
            throw new PWBoxError(e);
        } catch (BadPaddingException e) {
            throw new PWBoxError(e);
        } catch (InvalidKeyException e) {
            throw new PWBoxError(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new PWBoxError(e);
        }
    }

    /** Visible for testing. */
    byte[] decrypt(Key k, byte[] iv, byte[] encryptedText) {
        try {
            final Cipher c = Cipher.getInstance(CIPHER_SPEC);
            c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
            return c.doFinal(encryptedText);
        } catch (IllegalBlockSizeException e) {
            throw new PWBoxError(e);
        } catch (InvalidKeyException e) {
            throw new PWBoxError(e);
        } catch (BadPaddingException e) {
            throw new PWBoxError(e);
        } catch (NoSuchAlgorithmException e) {
            throw new PWBoxError(e);
        } catch (NoSuchPaddingException e) {
            throw new PWBoxError(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new PWBoxError(e);
        }
    }

    /** Visible for testing */
    byte[] hmac(Key k, byte[] text) {
        try {
            final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(k);
            return mac.doFinal(text);
        } catch (NoSuchAlgorithmException e) {
            throw new PWBoxError(e);
        } catch (InvalidKeyException e) {
            throw new PWBoxError(e);
        }
    }

    public byte[] encrypt(String passphrase, byte[] plaintext) throws PWBoxException, PWBoxError {
        try {
            // Prepare byte arrays of content in the same order as documented in the class docs, and
            // in the same order as the resulting bytes.
            final byte[] magic = "PWBox".getBytes("ASCII");

            final byte[] version = new byte[1];
            version[0] = 1;

            final byte[] markerIv = this.generateIv();
            final byte[] userEncIv = this.generateIv();
            final byte[] markerKeySalt = this.generateSalt();
            final byte[] userKeySalt = this.generateSalt();
            final byte[] hmacSalt = this.generateSalt();

            final Key markerKey = this.generateKey(passphrase, markerKeySalt);
            final Key userEncKey = this.generateKey(passphrase, userKeySalt);
            final Key hmacKey = this.generateKey(passphrase, hmacSalt);

            final byte[] encMarkerText = this.encrypt(markerKey, markerIv, CORRECT_PASSPHRASE_MARKER.getBytes("UTF-8"));
            if (encMarkerText.length != CORRECT_PASSPHRASE_MARKER_CRYPTED_LENGTH) {
                throw new PWBoxError("bug: encrypted correct passphrase marker not of expected length");
            }

            final byte[] encUserText = this.encrypt(userEncKey, userEncIv, plaintext);

            final ByteArrayOutputStream hmacOutputStream = new ByteArrayOutputStream();
            hmacOutputStream.write(userEncIv);
            hmacOutputStream.write(userKeySalt);
            hmacOutputStream.write(encUserText);
            final byte[] hmac = this.hmac(hmacKey, hmacOutputStream.toByteArray());

            final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            final DataOutputStream dout = new DataOutputStream(bout);
            dout.write(magic);
            dout.write(version);
            dout.write(markerIv);
            dout.write(userEncIv);
            dout.write(markerKeySalt);
            dout.write(userKeySalt);
            dout.write(hmacSalt);
            dout.write(hmac);
            dout.write(encMarkerText);
            dout.writeLong(encUserText.length);
            dout.write(encUserText);

            final byte[] encrypted = bout.toByteArray();

            // For pure paranoia. We are not concerned with performance given our premises.
            final byte[] decrypted = this.decrypt(passphrase, encrypted);
            if (!Arrays.equals(decrypted, plaintext)) {
                System.out.format("%h != %h", decrypted, plaintext);
                throw new PWBoxError("bug: decrypting what we just encrypted did not yield matching plaintext");
            }

            return encrypted;
        } catch (UnsupportedEncodingException e) {
            throw new PWBoxError(e);
        } catch (IOException e) {
            throw new PWBoxError(e);
        }
    }

    public byte[] decrypt(String passphrase, byte[] encryptedContent) throws PWBoxException, PWBoxError {
        try {
            final DataInputStream din = new DataInputStream(new ByteArrayInputStream(encryptedContent));

            final byte[] magic = "PWBox".getBytes("ASCII");
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
                    throw new UnsupportedFormatVersionException("only support version 1, got version " + rversion[0]);
                }
            } catch (EOFException e) {
                throw new TruncatedException("truncated before format version could be read");
            }

            final byte[] markerIv = new byte[16];
            final byte[] userEncIv = new byte[16];
            final byte[] markerKeySalt = new byte[32];
            final byte[] userKeySalt = new byte[32];
            final byte[] hmacSalt = new byte[32];
            final byte[] hmac = new byte[20];
            final byte[] encPphraseMarker = new byte[CORRECT_PASSPHRASE_MARKER_CRYPTED_LENGTH];

            try {
                din.readFully(markerIv);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading pphrase marker iv");
            }

            try {
                din.readFully(userEncIv);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encryption iv");
            }

            try {
                din.readFully(markerKeySalt);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading pphrase marker salt");
            }

            try {
                din.readFully(userKeySalt);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encryption salt");
            }

            try {
                din.readFully(hmacSalt);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading hmac salt");
            }

            try {
                din.readFully(hmac);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading hmac");
            }

            try {
                din.readFully(encPphraseMarker);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading passphrase marker");
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

            final Key markerKey = this.generateKey(passphrase, markerKeySalt);
            final Key userKey = this.generateKey(passphrase, userKeySalt);
            final Key hmacKey = this.generateKey(passphrase, hmacSalt);

            try {
                final byte[] plainMarker = this.decrypt(markerKey, markerIv, encPphraseMarker);
                if (!Arrays.equals(plainMarker, CORRECT_PASSPHRASE_MARKER.getBytes("UTF-8"))) {
                    throw new ProbablyBadPassphraseException();
                }
            } catch (PWBoxError e) {
                // This is kind of bogus. One example of an exception we could get is javax.crypto.BadPadingException,
                // instead of just getting back an incorrect passphrase. I do not like this variant since any bug
                // that causes an exception would mean that we claim bad passphrase. However, this can be improved
                // in a future version without changing the format (at least to the extent allowed by the Java API:s,
                // which I have not investigated).
                throw new ProbablyBadPassphraseException();
            }

            final ByteArrayOutputStream hmaced = new ByteArrayOutputStream();
            hmaced.write(userEncIv);
            hmaced.write(userKeySalt);
            hmaced.write(encUserText);
            final byte[] expectedHmac = this.hmac(hmacKey, hmaced.toByteArray());
            if (!Arrays.equals(expectedHmac, hmac)) {
                throw new InvalidHmacException("hmac did not match expectation - has data been tampered with? wrong passphrase?");
            }

            return this.decrypt(userKey, userEncIv, encUserText);
        } catch (UnsupportedEncodingException e) {
            throw new PWBoxError(e);
        } catch (IOException e) {
            throw new PWBoxError(e);
        }
    }
}
