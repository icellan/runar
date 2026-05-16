package runar.examples.fixedarraynested;

import java.util.ArrayList;
import java.util.List;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.FixedArray;

import static runar.lang.Builtins.assertThat;

/**
 * Grid2x2 -- minimal nested
 * {@code FixedArray<FixedArray<Bigint, 2>, 2>} acceptance contract for
 * the Java port of the FixedArray feature.
 *
 * <p>Ports {@code examples/python/fixed-array-nested/Grid2x2.v2.runar.py}
 * to Java. The expand-fixed-arrays pass in the Rúnar compiler desugars
 * {@code grid} into four scalar siblings
 * {@code grid__0__0, grid__0__1, grid__1__0, grid__1__1}; pass 3b
 * attaches a two-element {@code synthetic_array_chain} to each leaf, and
 * the iterative regrouper in the artifact assembler rebuilds a single
 * nested FixedArray state field so the SDK exposes {@code state.grid} as
 * a real nested array matching the declared shape.
 *
 * <p>Runtime indexing into a nested FixedArray is still a compile error
 * for the v1 spike, so each write is split into its own literal-index
 * method.
 *
 * <p><strong>Java compile-check note.</strong> Java's type system does not
 * allow integer values as type arguments, so a Rúnar Java surface
 * contract cannot embed a {@code FixedArray<T, N>} length in the type
 * itself the way TypeScript / Python / Ruby do. The Rúnar Java frontend
 * therefore does not accept this source file via {@code CompileCheck};
 * codegen-level conformance for nested FixedArray contracts is exercised
 * through the other 6 compiler tiers via the shared conformance suite.
 * This source file is consumed only by the off-chain
 * {@link runar.lang.runtime.ContractSimulator}, which uses the runtime
 * {@link FixedArray} value type directly.
 */
class Grid2x2 extends StatefulSmartContract {

    private static final FixedArray<Bigint> ZERO_ROW = FixedArray.of(
        2,
        Bigint.ZERO, Bigint.ZERO
    );

    private static final FixedArray<FixedArray<Bigint>> ZERO_GRID = FixedArray.of(
        2,
        ZERO_ROW, ZERO_ROW
    );

    FixedArray<FixedArray<Bigint>> grid = ZERO_GRID;

    Grid2x2() {
        super();
    }

    @Public
    void set00(Bigint v) {
        this.grid = withCell(0, 0, v);
        assertThat(true);
    }

    @Public
    void set01(Bigint v) {
        this.grid = withCell(0, 1, v);
        assertThat(true);
    }

    @Public
    void set10(Bigint v) {
        this.grid = withCell(1, 0, v);
        assertThat(true);
    }

    @Public
    void set11(Bigint v) {
        this.grid = withCell(1, 1, v);
        assertThat(true);
    }

    @Public
    void read00() {
        assertThat(this.grid.get(0).get(0).equals(this.grid.get(0).get(0)));
    }

    /**
     * Build a new 2x2 grid with the (row, col) cell replaced by {@code v}.
     * The Rúnar compiler's {@code expand_fixed_arrays} pass would turn an
     * indexed assignment in the source into a scalar-sibling write; here we
     * mirror that immutable rebuild at the JVM level so the simulator path
     * (which runs Java directly) behaves like the compiled artifact would.
     */
    private FixedArray<FixedArray<Bigint>> withCell(int row, int col, Bigint v) {
        List<FixedArray<Bigint>> rows = new ArrayList<>(this.grid.items());
        List<Bigint> next = new ArrayList<>(rows.get(row).items());
        next.set(col, v);
        rows.set(row, new FixedArray<>(2, next));
        return new FixedArray<>(2, rows);
    }
}
