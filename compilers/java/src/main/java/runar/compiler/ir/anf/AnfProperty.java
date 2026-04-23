package runar.compiler.ir.anf;

/**
 * {@code initialValue} is nullable; non-null when the property carries a
 * compile-time default from the source.
 */
public record AnfProperty(String name, String type, boolean readonly, ConstValue initialValue) {}
