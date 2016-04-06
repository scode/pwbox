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

    @Test
    public void fromLenientHex() {
        Assert.assertEquals(HexUtil.fromLenientHex(""), "");
        Assert.assertEquals(HexUtil.fromLenientHex("01"), "01");
        Assert.assertEquals(HexUtil.fromLenientHex("0102 0304\n0506\n\n  07"), "01020304050607");
    }

    @Test
    public void toLenientHex() {
        Assert.assertEquals(HexUtil.toLenientHex(""), "\n");
        Assert.assertEquals(HexUtil.toLenientHex(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
                "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"),
                "0102 0304 0506 0708 090a 0b0c 0d0e 0f10 1112 1314 1516 1718 191a 1b1c 1d1e 1f20\n" +
                "2122 2324 2526 2728 292a 2b2c 2d2e 2f30 3132 3334 3536 3738 393a 3b3c 3d3e 3f40\n");
    }
}
