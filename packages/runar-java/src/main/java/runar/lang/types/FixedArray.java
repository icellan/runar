package runar.lang.types;

import java.util.List;
import java.util.Objects;

/**
 * Compile-time fixed-size array. The Rúnar compiler treats
 * {@code FixedArray<T, N>} as a sized tuple that gets expanded to N
 * scalar properties during the ANF pass — the runtime representation
 * here is just a length-checked {@link List} so the Java-side contract
 * body can talk about {@code grid.items().get(0)} without needing a
 * primitive array with generic element type.
 *
 * <p>The type argument {@code N} is not expressible in Java's type
 * system, so the parser reads it from the type's generic signature at
 * parse time. At runtime we enforce the length constraint in the
 * constructor: callers pass the expected length explicitly and the
 * constructor throws on mismatch.
 *
 * <p>Instances are immutable; {@link #items()} returns an unmodifiable
 * view.
 *
 * @param <T> element type
 */
public final class FixedArray<T> {

    private final int length;
    private final List<T> items;

    public FixedArray(int length, List<T> items) {
        Objects.requireNonNull(items, "items");
        if (items.size() != length) {
            throw new IllegalArgumentException(
                "FixedArray length mismatch: declared " + length + ", got " + items.size()
            );
        }
        this.length = length;
        this.items = List.copyOf(items);
    }

    @SafeVarargs
    public static <T> FixedArray<T> of(int length, T... elements) {
        return new FixedArray<>(length, List.of(elements));
    }

    public int length() {
        return length;
    }

    public List<T> items() {
        return items;
    }

    public T get(int index) {
        return items.get(index);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof FixedArray<?> that
            && this.length == that.length
            && this.items.equals(that.items);
    }

    @Override
    public int hashCode() {
        return items.hashCode();
    }

    @Override
    public String toString() {
        return "FixedArray[" + length + "]" + items;
    }
}
