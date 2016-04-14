package org.scode.pwbox.tool;

public class Main {
    public static void main(String[] args) throws Exception {
        final String command;

        if (args.length > 0) {
            command = args[0];
        } else {
            command = "help";
        }

        if (command.equals("help")
                || command.equals("-h")
                || command.equals("--help")) {
            printHelp();
            System.exit(0);
        } else if (command.equals("encrypt")) {
            Commands.encrypt(System.in, System.out, new ConsolePassphraseReader());
        } else if (command.equals("decrypt")) {
            Commands.decrypt(System.in, System.out, new ConsolePassphraseReader());
        }
    }

    private static void printHelp() {
        System.err.println("Usage: java -jar pwbox.jar <command> [...]");
        System.err.println("");
        System.err.println("Commands:");
        System.err.println("");
        System.err.println("  help");
        System.err.println("");
        System.err.println("    Show this help, or if a command is given, show help for that command.");
        System.err.println("");
        System.err.println("  encrypt");
        System.err.println("");
        System.err.println("    Read stdin until EOF, encrypt it, and emit encrypted form on stdout.");
        System.err.println("");
        System.err.println("  decrypt");
        System.err.println("");
        System.err.println("    Read stdin until EOF, decrypt it, and emit decrypted form on stdout.");
    }
}
