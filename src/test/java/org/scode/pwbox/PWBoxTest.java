package org.scode.pwbox;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.UnsupportedEncodingException;
import java.security.Key;

public class PWBoxTest {
    @Test
    public void saltGenerationLength() {
        PWBox box = new PWBox();

        byte[] salt = box.generateSalt();

        Assert.assertEquals(salt.length, PWBox.SALT_LENGTH_IN_BYTES);
    }

    @Test
    public void saltGenerationNoDupe() {
        PWBox box = new PWBox();

        Assert.assertNotEquals(box.generateSalt(), box.generateSalt());
    }

    @Test
    public void keyGenerationSuccess() {
        PWBox box = new PWBox();

        box.generateKey("passphrase", box.generateSalt());
    }

    @Test
    public void keyGenerationConsistent() {
        PWBox box = new PWBox();

        byte[] salt = box.generateSalt();

        Key k1 = box.generateKey("passphrase", salt);
        Key k2 = box.generateKey("passphrase", salt);

        box = new PWBox();

        Key k3 = box.generateKey("passphrase", salt);

        Assert.assertEquals(k1, k2);
        Assert.assertEquals(k2, k3);
    }

    @Test
    public void encryptDecryptInternal() {
        PWBox box = new PWBox();

        byte[] salt = box.generateSalt();
        byte[] iv = box.generateIv();

        Key key = box.generateKey("passphrase", salt);

        byte[] plaintext = new byte[1];
        plaintext[0] = '!';
        byte[] encrypted = box.encrypt(key, iv, plaintext);
        key = box.generateKey("passphrase", salt);
        byte[] decrypted = box.decrypt(key, iv, encrypted);

        Assert.assertEquals(plaintext, decrypted);
    }

    @Test
    public void hmacSuccess() throws UnsupportedEncodingException {
        PWBox box = new PWBox();

        byte[] salt = box.generateSalt();
        Key key = box.generateKey("passphrase", salt);
        box.hmac(key, "text".getBytes("UTF-8"));
    }

    @Test
    public void encryptDecrypt() throws UnsupportedEncodingException, PWBoxException {
        PWBox box = new PWBox();

        String passphrase = "passphrase";
        byte[] plaintext = "there once was a secret in a unit test".getBytes("UTF-8");

        byte[] encrypted = box.encrypt(passphrase, plaintext);
        byte[] decrypted = box.decrypt(passphrase, encrypted);

        Assert.assertEquals(decrypted, plaintext);
    }

    @Test
    public void tamperingThrows() throws UnsupportedEncodingException, PWBoxException {
        PWBox box = new PWBox();

        byte[] encrypted = box.encrypt("passphrase", "sooooper seeeeekrit".getBytes("UTF-8"));

        box.decrypt("passphrase", encrypted);

        // Mutate one byte at a time and ensure we fail with an error in all cases, and that the error is
        // either a PWBoxError or a PWBoxException.
        byte[] tmp = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            System.arraycopy(encrypted, 0, tmp, 0, encrypted.length);
            ++tmp[i];
            try {
                box.decrypt("passphrase", tmp);
                throw new AssertionError("box.decrypt() should not succeed with tampered input (byte pos = " + i + ")");
            } catch (PWBoxException e) {
                // ok
            } catch (PWBoxError e) {
                // ok
            }

        }
    }

    @Test
    public void decryptOld() throws UnsupportedEncodingException, PWBoxException {
        PWBox box = new PWBox();

        String passphrase = "passphrase";
        byte[] plaintext = "there once was a secret in a unit test".getBytes("UTF-8");

        if (false) {
            byte[] encrypted = box.encrypt(passphrase, plaintext);
            StringBuffer hex = new StringBuffer();
            for (byte b : encrypted) {
                hex.append(String.format("%02x", b));
            }
            System.out.println("ENC-HEX:" + hex);
        } else {
            String hex = "5057426f7800d5e9110ce095587a11cfb321fa17aee252b2cb5546d3aa4a534d09cf3a13c005ef11bad92b9c4eeb980550b813530c8a4a4d23c955fc9be6e1ce5d316275a2ca72ee6bbcf9552b0920fe2734200ca7c57d341b5385bad775406f9c7964e492e03e9aa2fb000000000000003050d40faf4dd6594a87c95748978bc780db16316bc314752c8e62efd92040d7d5bb51b17b35d6509f7fb46a7671e0450c";
            byte[] encrypted = hex2bytes(hex);
            byte[] decrypted = box.decrypt(passphrase, encrypted);
            Assert.assertEquals(decrypted, plaintext);
        }
    }

    public static byte[] hex2bytes(String s) {
        int len = s.length();
        byte[] arr = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            arr[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return arr;
    }
}
