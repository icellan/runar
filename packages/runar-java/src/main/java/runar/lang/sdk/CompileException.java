package runar.lang.sdk;

import java.util.List;

/**
 * Thrown by {@link CompileCheck} when the Rúnar frontend rejects a contract.
 * Carries the list of structured errors from whichever pass failed
 * (parse / validate / expand-fixed-arrays / typecheck).
 */
public final class CompileException extends RuntimeException {

    private final List<String> errors;

    public CompileException(String message, List<String> errors) {
        super(buildMessage(message, errors));
        this.errors = List.copyOf(errors);
    }

    public CompileException(String message, List<String> errors, Throwable cause) {
        super(buildMessage(message, errors), cause);
        this.errors = List.copyOf(errors);
    }

    public List<String> errors() {
        return errors;
    }

    private static String buildMessage(String message, List<String> errors) {
        if (errors == null || errors.isEmpty()) return message;
        StringBuilder sb = new StringBuilder(message).append(":");
        for (String err : errors) sb.append("\n  ").append(err);
        return sb.toString();
    }
}
