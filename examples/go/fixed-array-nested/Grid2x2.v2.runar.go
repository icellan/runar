package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Grid2x2 is a minimal nested `FixedArray<FixedArray<bigint, 2>, 2>`
// acceptance contract for the Go port of the FixedArray feature.
//
// The expand-fixed-arrays pass desugars `Grid` into four scalar siblings
// `grid__0__0`, `grid__0__1`, `grid__1__0`, `grid__1__1`. The pass
// attaches a two-element SyntheticArrayChain to each leaf, and the
// iterative regrouper in the artifact assembler rebuilds a single
// nested FixedArray state field so the SDK exposes `state.grid` as a
// real Go slice-of-slices matching the declared shape.
//
// Runtime indexing into a nested FixedArray is intentionally a compile
// error in the v1 spike, so each write is split into its own
// literal-index method.
type Grid2x2 struct {
	runar.StatefulSmartContract
	Grid [2][2]runar.Bigint
}

func (c *Grid2x2) init() {
	c.Grid = [2][2]runar.Bigint{{0, 0}, {0, 0}}
}

func (c *Grid2x2) Set00(v runar.Bigint) {
	c.Grid[0][0] = v
	runar.Assert(true)
}

func (c *Grid2x2) Set01(v runar.Bigint) {
	c.Grid[0][1] = v
	runar.Assert(true)
}

func (c *Grid2x2) Set10(v runar.Bigint) {
	c.Grid[1][0] = v
	runar.Assert(true)
}

func (c *Grid2x2) Set11(v runar.Bigint) {
	c.Grid[1][1] = v
	runar.Assert(true)
}

func (c *Grid2x2) Read00() {
	runar.Assert(c.Grid[0][0] == c.Grid[0][0])
}
