package org.scode.pwbox;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.UnsupportedEncodingException;

public class PWBoxTest {
    @Test
    public void encryptDecryptDoesNotCorrupt() throws PWBoxException, UnsupportedEncodingException {
        final byte[] encrypted = PWBox.encrypt(PWBox.Version.LATEST, "passphrase", "secret".getBytes("UTF-8"));
        final byte[] plain = PWBox.decrypt("passphrase", encrypted);

        Assert.assertEquals(plain, "secret".getBytes("UTF-8"));
    }
}
