package runar.lang.sdk;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.passes.ExpandFixedArrays;
import runar.compiler.passes.Typecheck;
import runar.compiler.passes.Validate;

/**
 * Runs the Rúnar frontend (parse → validate → expand-fixed-arrays → typecheck)
 * on a Rúnar contract. Mirrors the Go {@code runar.CompileCheck},
 * Rust {@code runar::compile_check}, and Python {@code runar.compile_check}
 * APIs — frontend only, no codegen.
 *
 * <p>Use in JUnit tests alongside business-logic tests to ensure a contract
 * will compile to Bitcoin Script:
 *
 * <pre>{@code
 * @Test
 * void testCompile() throws Exception {
 *     CompileCheck.run(Path.of("Counter.runar.java"));
 * }
 * }</pre>
 */
public final class CompileCheck {

    private CompileCheck() {}

    /**
     * Run the Rúnar frontend on a contract source string. Dispatches by
     * the file extension carried in {@code fileName} (must end in one of
     * {@code .runar.{ts,sol,move,go,rs,py,zig,rb,java}}).
     *
     * @throws CompileException if any frontend pass reports errors
     */
    public static void check(String source, String fileName) {
        ContractNode contract;
        try {
            contract = ParserDispatch.parse(source, fileName);
        } catch (ParserDispatch.ParseException e) {
            throw new CompileException(
                "parse errors in " + fileName,
                List.of(e.getMessage()),
                e
            );
        } catch (RuntimeException e) {
            throw new CompileException(
                "parse errors in " + fileName,
                List.of(e.getMessage() == null ? e.toString() : e.getMessage()),
                e
            );
        }

        try {
            Validate.run(contract);
        } catch (Validate.ValidationException e) {
            throw new CompileException(
                "validation errors in " + fileName,
                e.errors(),
                e
            );
        }

        try {
            contract = ExpandFixedArrays.run(contract);
        } catch (ExpandFixedArrays.ExpandException e) {
            throw new CompileException(
                "expand-fixed-arrays errors in " + fileName,
                e.errors(),
                e
            );
        }

        try {
            Typecheck.run(contract);
        } catch (Typecheck.TypeCheckException e) {
            throw new CompileException(
                "type-check errors in " + fileName,
                e.errors(),
                e
            );
        }
    }

    /**
     * Read a Rúnar contract from disk and run the frontend on it.
     * Equivalent to {@code check(Files.readString(file), file.toString())}.
     *
     * @throws IOException      if the file cannot be read
     * @throws CompileException if any frontend pass reports errors
     */
    public static void run(Path file) throws IOException {
        String source = Files.readString(file);
        check(source, file.toString());
    }
}
