# runar-zig

Native Zig runtime and testing support for `.runar.zig` contracts.

`packages/runar-zig` provides the `runar` module used by the Zig examples and their adjacent `*_test.zig` files. It is the Zig-side equivalent of the native helper packages used by the Go, Rust, and Python example trees.

Current scope:

- contract-facing names imported as `const runar = @import("runar");`
- compile-check helpers: `compileCheckSource`, `compileCheckFile`
- deterministic fixtures: `ALICE`, `BOB`, `CHARLIE`
- native helper/runtime surface used by the Zig example tests

This package is for native authoring and testing. It is not yet a full deployment SDK.

## Run tests

```bash
cd packages/runar-zig
zig build test
```

## Example suite

```bash
cd examples/zig
zig build test
```
