package org.scode.pwbox;

public class UnsupportedFormatVersionException extends PWBoxException {
    public UnsupportedFormatVersionException() {
    }

    public UnsupportedFormatVersionException(String s) {
        super(s);
    }

    public UnsupportedFormatVersionException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public UnsupportedFormatVersionException(Throwable throwable) {
        super(throwable);
    }
}
