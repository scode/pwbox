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
    public void badPassphrase() throws UnsupportedEncodingException, PWBoxException {
        PWBox box = new PWBox();

        byte[] encrypted = box.encrypt("passphrase", "secret".getBytes("UTF-8"));
        box.decrypt("passphrase", encrypted);

        try {
            box.decrypt("bad passphrase", encrypted);
            throw new AssertionError("decryption should have failed");
        } catch (ProbablyBadPassphraseException e) {
            // ok
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
            String hex = "5057426f780006a3f6d156fb856c2c0d14a7b2ff2dde71779dd5359b70c439610e22e6dcfb0538fb44bce0f7a5c1f0b6461955919b2809ce7215d256dc3376adad0efa004648ae6e9693811dd217ec55e0d3aedd35afb2a96e948f77a4780fe42c871650055a70638f36521f565a0f4fac646a1433c4bd65158c099d850113bca5f84d99c4ce46ab6fde06c810a2b835a27b79b134f56330f7de114318786883b36b78d1cc789057977315053b4f198f79ef75c4fcb503a7d765485da0174f99a3ce2cbfc2e1b10df68d0000000000000030ea1c7a6d590f17f7e3cf1835983308711b9a6367b9f57e155289deaa0e908a2fda508584ba285d21c563adee76382ed7";
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
