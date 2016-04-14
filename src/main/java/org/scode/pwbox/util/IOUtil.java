package org.scode.pwbox.util;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

public class IOUtil {
    private static final int IO_BUF_SIZE = 1024;

    public static void pipe(InputStream in, OutputStream out) throws IOException {
        final byte[] buf = new byte[IO_BUF_SIZE];

        while (true) {
            final int bytesRead = in.read(buf, 0, buf.length);

            if (bytesRead == -1) {
                break;
            }

            out.write(buf, 0, bytesRead);
        }
    }

    public static byte[] slurp(Path p) throws IOException {
        try(final ByteArrayOutputStream bout = new ByteArrayOutputStream();
            final FileInputStream fin = new FileInputStream(p.toFile())) {
            pipe(fin, bout);
            return bout.toByteArray();
        }
    }
}
