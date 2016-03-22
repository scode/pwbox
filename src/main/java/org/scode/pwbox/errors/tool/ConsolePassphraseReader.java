package org.scode.pwbox.errors.tool;

import java.io.Console;

public class ConsolePassphraseReader implements IPassphraseReader {
    @Override
    public String readPassphrase() {
        return new String(System.console().readPassword("Passphrase: "));
    }
}
