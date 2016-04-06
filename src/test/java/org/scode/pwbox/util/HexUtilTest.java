package org.scode.pwbox.util;

import org.testng.Assert;
import org.testng.annotations.Test;

public class HexUtilTest {
    @Test
    public void fromHexEmpty() throws HexUtil.InvalidHexException {
        Assert.assertEquals(HexUtil.fromHex(""), new byte[0]);
    }

    @Test
    public void toHexEmpty() {
        Assert.assertEquals(HexUtil.toHex(new byte[0]), "");
    }

    @Test
    public void fromHexWhoseLengthIsNotMultipleOfTwo() {
        try {
            HexUtil.fromHex("f");
            throw new AssertionError("should not be reached");
        } catch (HexUtil.InvalidHexException e) {
            // expected
        }
    }

    @Test
    public void fromHexInvalidCharacter() {
        try {
            HexUtil.fromHex("q");
            throw new AssertionError("should not be reached");
        } catch (HexUtil.InvalidHexException e) {
            // expected
        }
    }

    @Test
    public void allBytesPreserved() throws HexUtil.InvalidHexException {
        final byte[] allBytes = new byte[Byte.MAX_VALUE + 1];

        for (int i = 0; i < allBytes.length; i++) {
            allBytes[i] = (byte)i;
        }

        Assert.assertEquals(HexUtil.fromHex(HexUtil.toHex(allBytes)), allBytes);
    }

    @Test
    public void fromHexEdges() throws HexUtil.InvalidHexException {
        Assert.assertEquals(HexUtil.fromHex("00"), new byte[]{(byte)0});
        Assert.assertEquals(HexUtil.fromHex("7f"), new byte[]{(byte)127});
        Assert.assertEquals(HexUtil.fromHex("80"), new byte[]{(byte)128});
        Assert.assertEquals(HexUtil.fromHex("ff"), new byte[]{(byte)255});
    }

    @Test
    public void toHexEdges() {
        Assert.assertEquals(HexUtil.toHex(new byte[]{(byte)0}), "00");
        Assert.assertEquals(HexUtil.toHex(new byte[]{(byte)127}), "7f");
        Assert.assertEquals(HexUtil.toHex(new byte[]{(byte)128}), "80");
        Assert.assertEquals(HexUtil.toHex(new byte[]{(byte)255}), "ff");
    }
}
