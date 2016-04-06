package org.scode.pwbox.tool;

public class Main {
    public static void main(String[] args) {
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
    }
}
