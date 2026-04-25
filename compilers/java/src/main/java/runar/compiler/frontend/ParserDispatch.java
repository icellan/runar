package runar.compiler.frontend;

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

    /**
     * Parse {@code source} into a {@link ContractNode}, dispatching by the
     * format suffix in {@code filename}. Recognised suffixes:
     * {@code .runar.{ts,sol,move,py,go,rs,zig,rb,java}}.
     */
    public static ContractNode parse(String source, String filename) throws ParseException {
        String lower = filename == null ? "" : filename.toLowerCase();
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

    /** Unified parse-error type that adapts the per-parser exceptions. */
    public static final class ParseException extends Exception {
        public ParseException(String message) {
            super(message);
        }
        public ParseException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
