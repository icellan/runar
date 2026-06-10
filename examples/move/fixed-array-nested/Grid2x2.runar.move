// Grid2x2 — Move-style port of `examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts`.
//
// Exercises the nested fixed-array surface syntax in the `.runar.move`
// frontend. Move's `vector<T>` is dynamic-length and has no direct
// fixed-array analogue, so the Rúnar Move frontend uses a synthetic
// generic struct `FixedArray<T, N>` instead. Nested forms parse the
// `>>` close as two `>` (the lexer eagerly forms a shift token, so the
// parser splits it back into two single-`>` closes when terminating a
// generic argument list).
module Grid2x2 {
    use runar::StatefulSmartContract;
    use runar::types::{};

    resource struct Grid2x2 {
        grid: &mut FixedArray<FixedArray<bigint, 2>, 2> = [[0, 0], [0, 0]],
    }

    public fun set00(v: bigint) {
        self.grid[0][0] = v;
        assert!(true, 0);
    }

    public fun set01(v: bigint) {
        self.grid[0][1] = v;
        assert!(true, 0);
    }

    public fun set10(v: bigint) {
        self.grid[1][0] = v;
        assert!(true, 0);
    }

    public fun set11(v: bigint) {
        self.grid[1][1] = v;
        assert!(true, 0);
    }

    public fun read00() {
        assert!(self.grid[0][0] == self.grid[0][0], 0);
    }
}
