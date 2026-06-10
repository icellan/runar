package runar.lang.analyzer;

/**
 * Thrown for unrecoverable analyzer-input problems (non-hex characters,
 * I/O failures, etc.). Conformance fixtures never trigger this; it is
 * surfaced through the CLI's exit code when the input is malformed.
 */
public class AnalyzerException extends RuntimeException {
    public AnalyzerException(String message) {
        super(message);
    }

    public AnalyzerException(String message, Throwable cause) {
        super(message, cause);
    }
}
