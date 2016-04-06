package org.scode.pwbox.tool;

public class StaticPassphraseReader implements IPassphraseReader {
    private final String passphrase;

    public StaticPassphraseReader(String passphrase) {
        this.passphrase = passphrase;
    }
    @Override
    public String readPassphrase() {
        return this.passphrase;
    }
}
