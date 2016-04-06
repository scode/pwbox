package org.scode.pwbox.tool;

public class ConsolePassphraseReader implements IPassphraseReader {
    @Override
    public String readPassphrase() {
        return new String(System.console().readPassword("Passphrase: "));
    }
}
