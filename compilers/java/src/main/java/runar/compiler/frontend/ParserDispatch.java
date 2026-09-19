package runar.compiler.frontend;

import java.util.regex.Pattern;
import runar.compiler.ir.ast.ContractNode;

/**
 * Routes a Rúnar source file to the correct front-end parser based on its
 * {@code .runar.<lang>} file extension. Mirrors the dispatch logic found in
 * the other six compilers (TypeScript {@code 01-parse.ts}, Go {@code
 * frontend.ParseSource}, Rust {@code parser::parse_source}, Python {@code
 * parse_source}, Zig {@code parseSource}, Ruby {@code parse_source}).
 *
 * <p>All Rúnar surface formats produce identical {@link ContractNode} ASTs for
 * the same logical contract, so once dispatch lands the rest of the Java
 * pipeline is format-agnostic.
 */
public final class ParserDispatch {
    private ParserDispatch() {}

    // Author-facing comment directives implemented only by the TypeScript
    // compiler today: {@code @sighash <FLAGS>} (#123, per-method sighash type)
    // and {@code @embedAlways} (#109, readonly-field DCE opt-out). Word-boundary
    // anchored (\b) to mirror the TS {@code /@sighash\b/} / {@code
    // /@embedAlways\b/} scans so an identifier like {@code sighashType} does not
    // trip the guard.
    private static final Pattern SIGHASH_DIRECTIVE = Pattern.compile("@sighash\\b");
    private static final Pattern EMBED_ALWAYS_DIRECTIVE = Pattern.compile("@embedAlways\\b");
    private static final Pattern BINDING_VARIANT_DIRECTIVE = Pattern.compile("@bindingVariant\\b");

    /**
     * Parse {@code source} into a {@link ContractNode}, dispatching by the
     * format suffix in {@code filename}. Recognised suffixes:
     * {@code .runar.{ts,sol,move,py,go,rs,zig,rb,java}}.
     */
    public static ContractNode parse(String source, String filename) throws ParseException {
        // DoS-bound size guard. Reject oversized source BEFORE any
        // format-specific parser touches the input. Raises
        // InputLimits.SourceSizeExceededException (a ParseException
        // subclass) on rejection. BUG-008 follow-up.
        InputLimits.assertSourceBytesUnderLimit(source);

        String lower = filename == null ? "" : filename.toLowerCase();

        // Fail-closed guard, NARROWED to the 8 non-TypeScript surface formats
        // (#123/#109 port): the {@code @sighash} (#123, per-method sighash type)
        // and {@code @embedAlways} (#109, readonly-field DCE opt-out) comment
        // directives are honoured ONLY on the {@code .runar.ts} surface, which
        // the {@link TsParser} now parses directly. The other 8 frontends still
        // ignore comments, so they would silently drop these directives and
        // change signing / DCE semantics — keep rejecting them there until (if
        // ever) those tiers port the feature.
        if (source != null && !lower.endsWith(".runar.ts")) {
            if (SIGHASH_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@sighash directive is only supported on the .runar.ts surface "
                    + "(issue #123); write the contract in TypeScript syntax");
            }
            if (EMBED_ALWAYS_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@embedAlways directive is only supported on the .runar.ts surface "
                    + "(issue #109); write the contract in TypeScript syntax");
            }
            if (BINDING_VARIANT_DIRECTIVE.matcher(source).find()) {
                throw new ParseException(
                    "@bindingVariant directive is only supported on the .runar.ts surface; "
                    + "write the contract in TypeScript syntax");
            }
        }

        try {
            if (lower.endsWith(".runar.java")) {
                return JavaParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.ts")) {
                return TsParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.sol")) {
                return SolParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.move")) {
                return MoveParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.py")) {
                return PyParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.go")) {
                return GoParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.rs")) {
                return RustParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.zig")) {
                return ZigParser.parse(source, filename);
            }
            if (lower.endsWith(".runar.rb")) {
                return RbParser.parse(source, filename);
            }
        } catch (JavaParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (TsParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (SolParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (MoveParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (PyParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (GoParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (RustParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (ZigParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (RbParser.ParseException e) {
            throw new ParseException(e.getMessage(), e);
        } catch (RuntimeException e) {
            throw new ParseException(e.getMessage(), e);
        }
        throw new ParseException(
            "ParserDispatch: unrecognised file extension for " + filename
            + " (expected .runar.{ts,sol,move,py,go,rs,zig,rb,java})");
    }

    /** Unified parse-error type that adapts the per-parser exceptions.
     *  Non-final so {@link InputLimits.SourceSizeExceededException} can
     *  extend it for typed DoS-bound rejection (BUG-008 follow-up). */
    public static class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
        public ParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
