package runar.compiler.ir.anf;

import runar.compiler.ir.ast.SourceLocation;

/**
 * Single {@code let name = value} binding in an ANF method body.
 * {@code sourceLoc} is debug-only and NOT part of the conformance
 * boundary — canonical serialisation omits it.
 *
 * <p>Names follow the pattern {@code t0}, {@code t1}, … and are scoped
 * per method.
 */
public record AnfBinding(String name, AnfValue value, SourceLocation sourceLoc) {}
