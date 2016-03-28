package org.scode.pwbox.util;

import org.testng.Assert;
import org.testng.annotations.Test;

public class ByteUtilTest {
    @Test
    public void fromHexEmpty() throws ByteUtil.InvalidHexException {
        Assert.assertEquals(ByteUtil.fromHex(""), new byte[0]);
    }

    @Test
    public void toHexEmpty() {
        Assert.assertEquals(ByteUtil.toHex(new byte[0]), "");
    }

    @Test
    public void fromHexWhoseLengthIsNotMultipleOfTwo() {
        try {
            ByteUtil.fromHex("f");
            throw new AssertionError("should not be reached");
        } catch (ByteUtil.InvalidHexException e) {
            // expected
        }
    }

    @Test
    public void fromHexInvalidCharacter() {
        try {
            ByteUtil.fromHex("q");
            throw new AssertionError("should not be reached");
        } catch (ByteUtil.InvalidHexException e) {
            // expected
        }
    }

    @Test
    public void allBytesPreserved() throws ByteUtil.InvalidHexException {
        final byte[] allBytes = new byte[Byte.MAX_VALUE + 1];

        for (int i = 0; i < allBytes.length; i++) {
            allBytes[i] = (byte)i;
        }

        Assert.assertEquals(ByteUtil.fromHex(ByteUtil.toHex(allBytes)), allBytes);
    }

    @Test
    public void fromHexEdges() throws ByteUtil.InvalidHexException {
        Assert.assertEquals(ByteUtil.fromHex("00"), new byte[]{(byte)0});
        Assert.assertEquals(ByteUtil.fromHex("7f"), new byte[]{(byte)127});
        Assert.assertEquals(ByteUtil.fromHex("80"), new byte[]{(byte)128});
        Assert.assertEquals(ByteUtil.fromHex("ff"), new byte[]{(byte)255});
    }

    @Test
    public void toHexEdges() {
        Assert.assertEquals(ByteUtil.toHex(new byte[]{(byte)0}), "00");
        Assert.assertEquals(ByteUtil.toHex(new byte[]{(byte)127}), "7f");
        Assert.assertEquals(ByteUtil.toHex(new byte[]{(byte)128}), "80");
        Assert.assertEquals(ByteUtil.toHex(new byte[]{(byte)255}), "ff");
    }
}
