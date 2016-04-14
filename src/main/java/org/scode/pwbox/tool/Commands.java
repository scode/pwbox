package org.scode.pwbox.tool;

import org.scode.pwbox.PWBox1Impl;
import org.scode.pwbox.errors.PWBoxException;
import org.scode.pwbox.util.IOUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

public class Commands {
    public static void decrypt(final InputStream in,
                               final OutputStream out,
                               final IPassphraseReader preader) throws IOException, PWBoxException {
        final byte[] encBytes = IOUtil.slurp(in);

        // Intentionally use String(byte[], String) which will "silently" accept input data that does not
        // map.
        // TODO(scode): Consider using a stricter mode and emitting a warning, falling back to lenient
        // if requested by the user.
        final String encString = new String(encBytes, "UTF-8");
        final byte[] decBytes = new PWBox1Impl().decryptString(preader.readPassphrase(), encString);
        out.write(decBytes, 0, decBytes.length);
    }

    public static void encrypt(final InputStream in,
                               final OutputStream out,
                               final IPassphraseReader preader) throws IOException, PWBoxException {
        final byte[] decBytes = IOUtil.slurp(in);
        final String encString = new PWBox1Impl().encryptString(preader.readPassphrase(), decBytes);

        // TODO(scode): Consider what to do about unmappable characters.
        out.write(encString.getBytes("UTF-8"));
    }
}
