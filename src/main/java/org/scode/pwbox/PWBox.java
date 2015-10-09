package org.scode.pwbox;

/** A simple high-level passphrase based encryption and authentication library.
 *
 * Exactly two features are provided; encryption and decryption. For detailed usage, see each individual method.
 * For an overall documentation of the project, including information about the encryption and integrity
 * checking, see the README.
 *
 * Here is a simple example (minus exception handling):
 *
 * <pre>
 *     byte[] encrypted = PWBox.encrypt(PWBox.Format.DEFAULT, "passphrase", "secret".getBytes("UTF-8"));
 *     byte[] plain = PWBox.decrypt("passphrase", encrypted);
 * </pre>
 *
 * @see org.scode.pwbox.PWBoxException
 * @see org.scode.pwbox.PWBoxError
 */
public class PWBox {
    /**
     * The format of an encrypted PWBox byte array.
     */
    public enum Format {
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
