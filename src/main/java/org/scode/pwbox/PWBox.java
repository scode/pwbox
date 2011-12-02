package org.scode.pwbox;

public class PWBox {
    public static enum Format {
        /** Default (implementation defined) format. */
        DEFAULT,
        /** The first version of the format. */
        ONE,
    }

    public static byte[] encrypt(Format format, String passphrase, byte[] plainTextContent) throws PWBoxException, PWBoxError {
        switch (format) {
            case DEFAULT:
            case ONE:
                return new PWBox1Impl().encrypt(passphrase, plainTextContent);
            default:
                throw new AssertionError("invalid format requested");
        }
    }

    public static byte[] decrypt(String passphrase, byte[] encryptedContent) throws PWBoxException, PWBoxError {
        return new PWBox1Impl().decrypt(passphrase, encryptedContent);
    }
}
