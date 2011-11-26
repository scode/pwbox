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
 * Data format:
 *
 * The format of encrypted data is as follows:
 *
 * <code>
 *     Byte 00:      'P' ASCII code
 *     Byte 01:      'W" ASCII code
 *     Byte 02:      'B' ASCII code
 *     Byte 03:      'o' ASCII code
 *     Byte 04:      'x' ASCII code
 *     Byte 05:      0, indicating the zeroth version of the PWBox format
 *     Byte 06-21:   16 byte IV used for encryption
 *     Byte 22-53:   32 byte salt used for encryption key
 *     Byte 54-85:   32 byte salt used for HMAC key
 *     Byte 86-105:  20 bytes HMAC (SHA1) over iv + encryption key + encrypted text
 *     Byte 106-113: 8 bytes in DataOutputStream.writeLong() format of length of the remainder (for
 *                   truncation detection for user-friendly errors, not HMAC:ed).
 *     Byte 114-EOF: Encrypted text (AES/CBC/PKCS5PADDING)
 * </code>
 *
 */
public class PWBox implements IPWBox {
    /**
     * I chose salt length to be equal to key length on the hypothesis that a salt length larger than the key size
     * is useless, and I know of no reason to prefer a smaller one.
     */
    static final int SALT_LENGTH_IN_BYTES = 32;

    /**
     * The IV length must be 16 bytes long according to an InvalidAlgorithmParameterException which is otherwise
     * thrown by the AESCipher (tested on JDK 1.6 on MacOS). I am unfamiliar with the implications cryptographically.
     */
    static final int IV_LENGTH_IN_BYTES = 16;

    /**
     * The assumption of PWBox is that small amounts of data are being encrypted and decrypted, meaning that
     * the performance penalty of a larger key is irrelevant. So, go with 256 bits.
     */
    static final int KEY_LENGTH_IN_BITS = 256;

    /**
     * I chose 10000 based on ad-hoc performance measurements on my MacBook. Essentially, "unit tests still run fast,
     * so it's okay for the end-user that only needs to wait for a single key generation".
     */
    static final int PBE_ITERATION_COUNT = 10000;
    
    static final String ENCRYPTION_ALGORITHM = "AES";

    /**
     * I chose CTR over CBC because it was indicated to me that CBC would leak more information in the event of
     * a low-entropy IV.
     *
     * Given the premise of this library of small amounts of data, the potential for future parallel
     * encryption/decryption is not relevant.
     */
    static final String CIPHER_SPEC = "AES/CTR/PKCS5PADDING";
    static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA1";

    static final String HMAC_ALGORITHM = "HmacSHA1";

    Key generateKey(String passphrase, byte[] salt) {
        SecretKeyFactory f = null;
        try {
            f = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_ALGORITHM);
            KeySpec ks = new PBEKeySpec(passphrase.toCharArray(), salt, PBE_ITERATION_COUNT, KEY_LENGTH_IN_BITS);
            SecretKey s = f.generateSecret(ks);
            return new SecretKeySpec(s.getEncoded(), ENCRYPTION_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new PWBoxError(e);
        } catch (InvalidKeySpecException e) {
            throw new PWBoxError(e);
        }
    }

    byte[] generateSalt() {
        SecureRandom sr = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH_IN_BYTES];
        sr.nextBytes(salt);

        return salt;
    }

    byte[] generateIv() {
        SecureRandom sr = new SecureRandom();

        byte[] iv = new byte[IV_LENGTH_IN_BYTES];
        sr.nextBytes(iv);

        return iv;
    }

    byte[] encrypt(Key k, byte[] iv, byte[] plainText) {
        Cipher c = null;
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

    byte[] decrypt(Key k, byte[] iv, byte[] encryptedText) {
        try {
            Cipher c = Cipher.getInstance(CIPHER_SPEC);
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

    byte[] hmac(Key k, byte[] text) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(k);
            return mac.doFinal(text);
        } catch (NoSuchAlgorithmException e) {
            throw new PWBoxError(e);
        } catch (InvalidKeyException e) {
            throw new PWBoxError(e);
        }
    }

    @Override
    public byte[] encrypt(String passphrase, byte[] plaintext) throws PWBoxException, PWBoxError {
        try {
            byte[] magic = "PWBox".getBytes("ASCII");

            byte[] version = new byte[1];
            version[0] = 0; // Be explicit.

            byte[] iv = this.generateIv();
            byte[] encSalt = this.generateSalt();
            byte[] macSalt = this.generateSalt();

            Key encKey = this.generateKey(passphrase, encSalt);
            Key macKey = this.generateKey(passphrase, macSalt);

            byte[] encText = this.encrypt(encKey, iv, plaintext);

            ByteArrayOutputStream hmaced = new ByteArrayOutputStream();
            hmaced.write(iv);
            hmaced.write(encSalt);
            hmaced.write(encText);
            byte[] hmac = this.hmac(macKey, hmaced.toByteArray());

            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            DataOutputStream dout = new DataOutputStream(bout);
            dout.write(magic);
            dout.write(version);
            dout.write(iv);
            dout.write(encSalt);
            dout.write(macSalt);
            dout.write(hmac);
            dout.writeLong(encText.length);
            dout.write(encText);

            byte[] encrypted = bout.toByteArray();

            // For pure paranoia. We are not concerned with performance given our premises.
            byte[] decrypted = this.decrypt(passphrase, encrypted);
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

    @Override
    public byte[] decrypt(String passphrase, byte[] encryptedContent) throws PWBoxException, PWBoxError {
        try {
            DataInputStream din = new DataInputStream(new ByteArrayInputStream(encryptedContent));

            byte[] magic = "PWBox".getBytes("ASCII");
            try {
                byte[] rmagic = new byte[magic.length];
                din.readFully(rmagic);
                if (!Arrays.equals(magic, rmagic)) {
                    throw new InvalidMagicException("invalid magic - not PWBox data?");
                }
            } catch (EOFException e) {
                throw new InvalidMagicException("input data did not contain magic indicating it is PWBox data - too short");
            }

            byte[] rversion = new byte[1];
            try {
                din.readFully(rversion);
                if (rversion[0] != 0) {
                    throw new UnsupportedFormatVersionException("only support version 0, got version " + rversion[0]);
                }
            } catch (EOFException e) {
                throw new TruncatedException("truncated before format version could be read");
            }

            byte[] iv = new byte[16];
            byte[] encSalt = new byte[32];
            byte[] macSalt = new byte[32];
            byte[] hmac = new byte[20];

            try {
                din.readFully(iv);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading iv");
            }

            try {
                din.readFully(encSalt);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encryption salt");
            }

            try {
                din.readFully(macSalt);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading hmac salt");
            }

            try {
                din.readFully(hmac);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading hmac");
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

            byte[] encrypted = new byte[(int)len];
            try {
                din.readFully(encrypted);
            } catch (EOFException e) {
                throw new TruncatedException("data truncated reading encrypted text (expected " + len + " bytes after header)");
            }

            if (din.available() != 0) {
                throw new TrailingGarbageException("expected EOF after reading " + len + " bytes of encrypted text (after header)");
            }

            Key encKey = this.generateKey(passphrase, encSalt);
            Key macKey = this.generateKey(passphrase, macSalt);

            ByteArrayOutputStream hmaced = new ByteArrayOutputStream();
            hmaced.write(iv);
            hmaced.write(encSalt);
            hmaced.write(encrypted);
            byte[] expectedHmac = this.hmac(macKey, hmaced.toByteArray());
            if (!Arrays.equals(expectedHmac, hmac)) {
                throw new InvalidHmacException("hmac did not match expectation - has data been tampered with? wrong passphrase?");
            }

            return this.decrypt(encKey, iv, encrypted);
        } catch (UnsupportedEncodingException e) {
            throw new PWBoxError(e);
        } catch (IOException e) {
            throw new PWBoxError(e);
        }
    }
}
