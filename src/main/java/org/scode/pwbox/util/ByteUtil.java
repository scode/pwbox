package org.scode.pwbox.util;

public class ByteUtil {
    public static class InvalidHexException extends Exception {
        public InvalidHexException(String msg) {
            super(msg);
        }
    }

    public static String toHex(final byte[] bytes) {
        final StringBuffer buf = new StringBuffer();

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

    private static int hexChar(char ch) throws InvalidHexException {
        final int ret = Character.digit(ch, 16);

        if (ret == -1) {
            throw new InvalidHexException("encountered invalid hex character: " + ch);
        }

        return ret;
    }
}
