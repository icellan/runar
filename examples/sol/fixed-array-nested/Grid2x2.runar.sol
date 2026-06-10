pragma runar ^0.1.0;

/// Grid2x2 — Solidity-like port of `examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts`.
///
/// Exercises the nested fixed-array surface syntax `bigint[2][2]` in the
/// `.runar.sol` frontend. Per Solidity's array-of-arrays convention the
/// type reads outer-to-inner left-to-right: `T[A][B]` ⇒ outer `B` of inner
/// `A` of `T`, which lowers to `FixedArray<FixedArray<T, A>, B>` in the
/// Rúnar AST. For the symmetric 2×2 case the shape matches the TS
/// reference `FixedArray<FixedArray<bigint, 2>, 2>` exactly.
contract Grid2x2 is StatefulSmartContract {
    bigint[2][2] grid = [[0, 0], [0, 0]];

    constructor() {}

    function set00(bigint v) public {
        this.grid[0][0] = v;
        require(true);
    }

    function set01(bigint v) public {
        this.grid[0][1] = v;
        require(true);
    }

    function set10(bigint v) public {
        this.grid[1][0] = v;
        require(true);
    }

    function set11(bigint v) public {
        this.grid[1][1] = v;
        require(true);
    }

    function read00() public {
        require(this.grid[0][0] == this.grid[0][0]);
    }
}
