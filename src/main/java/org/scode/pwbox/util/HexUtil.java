package org.scode.pwbox.util;

public class HexUtil {
    public static class InvalidHexException extends Exception {
        public InvalidHexException(String msg) {
            super(msg);
        }
    }

    public static String toHex(final byte[] bytes) {
        final StringBuilder buf = new StringBuilder();

        for(byte b : bytes) {
            buf.append(Character.forDigit((b >> 4) & 0xF, 16));
            buf.append(Character.forDigit((b & 0xF), 16));
        }

        return buf.toString();
    }

    public static byte[] fromHex(final String hex) throws InvalidHexException {
        if (hex.length() % 2 != 0) {
            throw new InvalidHexException("string length not a multiple of 2: " + hex.length());
        }

        final byte[] ret = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            ret[i / 2] = (byte)((hexChar(hex.charAt(i)) << 4)
                    + hexChar(hex.charAt(i+1)));
        }

        return ret;
    }

    public static String toLenientHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("hex string not of size divisible by 2");
        }

        final StringBuilder ret = new StringBuilder();

        for (int i = 0; i < hex.length(); i++) {
            if (i > 0) {
                if (i % 64 == 0) {
                    ret.append('\n');
                } else if (i % 4 == 0) {
                    ret.append(' ');
                }
            }
            ret.append(hex.charAt(i));
        }

        ret.append('\n');

        return ret.toString();
    }

    public static String fromLenientHex(String lenientHex) {
        final StringBuilder ret = new StringBuilder();

        for (int i = 0; i < lenientHex.length(); i++) {
            final char ch = lenientHex.charAt(i);

            if (!Character.isWhitespace(ch)) {
                ret.append(ch);
            }
        }

        return ret.toString();
    }

    private static int hexChar(char ch) throws InvalidHexException {
        final int ret = Character.digit(ch, 16);

        if (ret == -1) {
            throw new InvalidHexException("encountered invalid hex character: " + ch);
        }

        return ret;
    }
}
