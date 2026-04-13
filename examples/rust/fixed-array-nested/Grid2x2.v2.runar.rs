use runar::prelude::*;

/// Grid2x2 -- minimal nested `[[Bigint; 2]; 2]` acceptance contract for
/// the Rust port of the FixedArray feature.
///
/// The expand-fixed-arrays pass desugars `grid` into four scalar siblings
/// `grid__0__0`, `grid__0__1`, `grid__1__0`, `grid__1__1`. Each leaf
/// carries a two-element `synthetic_array_chain`, and the iterative
/// regrouper in the artifact assembler rebuilds a single nested
/// FixedArray state field so the SDK exposes `state.grid` as a real
/// nested array matching the declared shape.
///
/// Runtime indexing into a nested FixedArray is intentionally still a
/// compile error for the v1 spike, so each write is split into its own
/// literal-index method.
#[runar::contract]
pub struct Grid2x2 {
    pub grid: [[Bigint; 2]; 2],
    pub tx_preimage: SigHashPreimage,
}

#[runar::methods(Grid2x2)]
impl Grid2x2 {
    pub fn init(&mut self) {
        self.grid = [[0, 0], [0, 0]];
    }

    #[public]
    pub fn set00(&mut self, v: Bigint) {
        self.grid[0][0] = v;
        assert!(true);
    }

    #[public]
    pub fn set01(&mut self, v: Bigint) {
        self.grid[0][1] = v;
        assert!(true);
    }

    #[public]
    pub fn set10(&mut self, v: Bigint) {
        self.grid[1][0] = v;
        assert!(true);
    }

    #[public]
    pub fn set11(&mut self, v: Bigint) {
        self.grid[1][1] = v;
        assert!(true);
    }

    #[public]
    pub fn read00(&self) {
        assert!(self.grid[0][0] == self.grid[0][0]);
    }
}
