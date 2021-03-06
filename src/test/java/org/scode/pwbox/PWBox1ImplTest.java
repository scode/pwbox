package org.scode.pwbox;

import org.scode.pwbox.errors.PWBoxError;
import org.scode.pwbox.errors.PWBoxException;
import org.scode.pwbox.errors.AuthenticationFailedException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.concurrent.TimeUnit;

public class PWBox1ImplTest {
    @Test
    public void encryptDecryptString() throws Exception {
        final PWBox1Impl box = new PWBox1Impl();

        Assert.assertEquals(box.decryptString("pass", box.encryptString("pass", "plaintext".getBytes())),
                "plaintext".getBytes());
    }

    @Test
    public void saltGenerationLength() {
        final PWBox1Impl box = new PWBox1Impl();

        final byte[] salt = box.generateSalt();

        Assert.assertEquals(salt.length, PWBox1Impl.SALT_LENGTH_IN_BYTES);
    }

    @Test
    public void saltGenerationNoDupe() {
        final PWBox1Impl box = new PWBox1Impl();

        Assert.assertNotEquals(box.generateSalt(), box.generateSalt());
    }

    @Test
    public void keyGenerationSuccess() {
        final PWBox1Impl box = new PWBox1Impl();

        box.generateKey("passphrase", box.generateSalt());
    }

    @Test
    public void keyGenerationConsistent() {
        PWBox1Impl box = new PWBox1Impl();

        final byte[] salt = box.generateSalt();

        final Key k1 = box.generateKey("passphrase", salt);
        final Key k2 = box.generateKey("passphrase", salt);

        box = new PWBox1Impl();

        final Key k3 = box.generateKey("passphrase", salt);

        Assert.assertEquals(k1, k2);
        Assert.assertEquals(k2, k3);
    }

    @Test
    public void encryptDecryptInternal() throws Exception {
        final PWBox1Impl box = new PWBox1Impl();

        final byte[] salt = box.generateSalt();
        final byte[] iv = box.generateIv();

        Key key = box.generateKey("passphrase", salt);

        final byte[] plaintext = new byte[1];
        plaintext[0] = '!';
        final byte[] encrypted = box.encrypt(key, iv, plaintext);
        key = box.generateKey("passphrase", salt);
        final byte[] decrypted = box.decrypt(key, iv, encrypted);

        Assert.assertEquals(plaintext, decrypted);
    }

    @Test
    public void encryptDecrypt() throws UnsupportedEncodingException, PWBoxException {
        final PWBox1Impl box = new PWBox1Impl();

        final String passphrase = "passphrase";
        final byte[] plaintext = "there once was a secret in a unit test".getBytes("UTF-8");

        final byte[] encrypted = box.encrypt(passphrase, plaintext);
        final byte[] decrypted = box.decrypt(passphrase, encrypted);

        Assert.assertEquals(decrypted, plaintext);
    }

    /**
     * In order to run a meaninful number of iterations, and to enable printing results, increase this to a higher
     * number.
     */
    private static final int PERF_TEST_ITERATION_COUNT = 1;
    @Test
    public void keyStretchingPerfTest() throws Exception {
        // Spend a relatively small amount of time on warm-up.
        for (int i = 0; i < PERF_TEST_ITERATION_COUNT / 20; i++) {
            final PWBox1Impl box = new PWBox1Impl();
            final byte[] encrypted = box.encrypt("passphrase", "s".getBytes("UTF-8"));
        }

        final long startTime = System.nanoTime();
        for (int i = 0; i < PERF_TEST_ITERATION_COUNT; i++) {
            final PWBox1Impl box = new PWBox1Impl();
            final byte[] encrypted = box.encrypt("passphrase", "s".getBytes("UTF-8"));
        }
        final long stopTime = System.nanoTime();

        final long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(stopTime - startTime);
        final long persec = PERF_TEST_ITERATION_COUNT * elapsedMillis / 1000;

        if (PERF_TEST_ITERATION_COUNT > 1) { // suppress false claim unless iteration count has been modified
            System.out.println("" + PERF_TEST_ITERATION_COUNT + " in " + elapsedMillis + " ms -> "
                    + persec + " per second");
        }
    }

    @Test
    public void tamperingThrows() throws UnsupportedEncodingException, PWBoxException {
        final PWBox1Impl box = new PWBox1Impl();

        final byte[] encrypted = box.encrypt("passphrase", "sooooper seeeeekrit".getBytes("UTF-8"));

        box.decrypt("passphrase", encrypted);

        // Mutate one byte at a time and ensure we fail with an error in all cases, and that the error is
        // either a PWBoxError or a PWBoxException.
        final byte[] tmp = new byte[encrypted.length];
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
        final PWBox1Impl box = new PWBox1Impl();

        final byte[] encrypted = box.encrypt("passphrase", "secret".getBytes("UTF-8"));
        box.decrypt("passphrase", encrypted);

        try {
            box.decrypt("bad passphrase", encrypted);
            throw new AssertionError("decryption should have failed");
        } catch (AuthenticationFailedException e) {
            // ok
        }
    }

    @Test
    public void decryptOld() throws UnsupportedEncodingException, PWBoxException {
        final PWBox1Impl box = new PWBox1Impl();

        final String passphrase = "passphrase";
        final byte[] plaintext = "there once was a secret in a unit test".getBytes("UTF-8");

        // Detect whether the implementation changes its output in any way. Flip to true to generate
        // the original hex which appears inline in the second arm of the if.
        if (true) { // TODO(scode): See KEY_LENGTH_IN_BITS
            final byte[] encrypted = box.encrypt(passphrase, plaintext);
            final StringBuilder hex = new StringBuilder();
            for (byte b : encrypted) {
                hex.append(String.format("%02x", b));
            }
            System.out.println("ENC-HEX:" + hex);
        } else {
            final String hex = "5057426f7801fa89a5e0ddb266e9dd3e50be4e8724ccc7e478048d133a0aa764d3765aabf77f0a1480b65053616c8ddd4c155ddd00f342cad78cb741e436107acace1d0cdfdf732cd43bc241e9b4e8361ade933051bc8137f8d036bd0a4e063f17591ec942936fa5e61cd9169bcda4688c3f587fc63bd4a0506214cc17643839bcafb0c78086b0eef35a6e0f14ad3751cb3660ef49978789a69bf3dc6c8f805492bd8f4fd368a16cdb3e70e5e6a21b123d4c7797570625190035a327d0070163c9b5bd824dda9bf8ab4b0000000000000030366b7a756db3661006a57aaad4ef2e3dbedc5541b69c299ce94bf546c47389901ffd196bd2a0155225bf6e1a0f2b1b1d";
            final byte[] encrypted = hex2bytes(hex);
            final byte[] decrypted = box.decrypt(passphrase, encrypted);
            Assert.assertEquals(decrypted, plaintext);
        }
    }

    public static byte[] hex2bytes(String s) {
        final int len = s.length();
        final byte[] arr = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            arr[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return arr;
    }
}
