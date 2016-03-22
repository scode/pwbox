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
 *     byte[] encrypted = PWBox.encrypt(PWBox.Version.LATEST, "passphrase", "secret".getBytes("UTF-8"));
 *     byte[] plain = PWBox.decrypt("passphrase", encrypted);
 * </pre>
 *
 * @see org.scode.pwbox.PWBoxException
 * @see org.scode.pwbox.PWBoxError
 */
public class PWBox {
    /**
     * The version (on-disk wire format) of an encrypted PWBox byte array.
     */
    public enum Version {
        /** Default (implementation defined) format. */
        LATEST,
        /** The first version of the format. */
        ONE,
    }

    public static byte[] encrypt(Version version, String passphrase, byte[] plainTextContent) throws PWBoxException, PWBoxError {
        switch (version) {
            case LATEST:
            case ONE:
                return new PWBox1Impl().encrypt(passphrase, plainTextContent);
            default:
                throw new AssertionError("invalid version requested: " + version);
        }
    }

    public static byte[] decrypt(String passphrase, byte[] encryptedContent) throws PWBoxException, PWBoxError {
        return new PWBox1Impl().decrypt(passphrase, encryptedContent);
    }
}
