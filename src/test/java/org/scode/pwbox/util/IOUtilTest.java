package org.scode.pwbox.util;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class IOUtilTest {
    @Test
    public void testPipeEmpty() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ByteArrayInputStream in = new ByteArrayInputStream(new byte[0]);

        IOUtil.pipe(in, out);

        Assert.assertEquals(out.toByteArray(), new byte[0]);
    }

    @Test
    public void testNonEmpty() throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ByteArrayInputStream in = new ByteArrayInputStream("hello".getBytes());

        IOUtil.pipe(in, out);

        Assert.assertEquals(out.toByteArray(), "hello".getBytes());
    }
}
