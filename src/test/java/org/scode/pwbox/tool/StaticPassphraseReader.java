package org.scode.pwbox.tool;

import org.scode.pwbox.errors.tool.IPassphraseReader;

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
