package org.scode.pwbox;

public interface IPWBox {
    public byte[] encrypt(String passphrase, byte[] plainTextContent) throws PWBoxException, PWBoxError;
    public byte[] decrypt(String passphrase, byte[] encryptedContent) throws PWBoxException, PWBoxError;
}
