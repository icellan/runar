# `conformance/sdk-codegen/` — cross-SDK typed-wrapper conformance

Companion to `conformance/sdk-output/` (which verifies byte-identical
*compiled-script* output across compilers). This suite verifies that the
**typed-wrapper code generators** in every SDK (`packages/runar-{sdk,go,
rs,py,java,rb,zig}`) produce structurally-equivalent output for the same
artifact, and that the output compiles cleanly in every host language.

It exists because string-pattern tests inside individual SDKs missed a
real bug — see the manifest's intro for the post-mortem.

## Layout

```
conformance/sdk-codegen/
├── MANIFEST.md           # the contract every SDK must satisfy
├── README.md             # this file
└── fixtures/             # shared artifact JSONs
    ├── p2pkh.json          # stateless + Sig param
    ├── counter.json        # stateful, mixed terminal/non-terminal
    ├── simple.json         # no constructor params
    ├── stateful-escrow.json # stateful + multi-Sig
    └── inscribed.json      # attachInscription path
```

There is no `runners/` subdirectory here — that layout was documented but
never actually built for any tier. Each SDK's runner instead lives inside
that SDK's own test tree, loading the fixtures above by relative path, the
same way every other cross-tier fixture suite in this repo
(`conformance/sdk-envelope/`, `conformance/sdk-call/`, …) is consumed:

| Tier | Runner | Coverage |
| --- | --- | --- |
| TypeScript (reference) | `packages/runar-sdk/src/__tests__/f297-codegen-conformance.test.ts` | all 5 fixtures, structural + transpile-and-execute against the real `RunarContract` |
| Java | `packages/runar-java/src/test/java/runar/lang/sdk/codegen/CodegenConformanceTest.java` | all 5 fixtures, structural + in-memory `javac` compile |
| Ruby | `packages/runar-rb/spec/sdk/codegen_conformance_spec.rb` | all 5 fixtures, structural + `RubyVM::InstructionSequence.compile` syntax check |
| Zig | `packages/runar-zig/src/sdk_codegen_conformance_test.zig` | all 5 fixtures (inlined as comptime literals — Zig can't `@embedFile` outside the package boundary), structural only (see `codegen-compile-check` below for the compile step this tier lacked) |
| Go | `packages/runar-go/sdk_codegen_test.go` | 2 of 5 fixtures (counter, p2pkh), Go-shape-only assertions, `go vet` compile + a real end-to-end deploy/call against `MockProvider` |
| Rust | `packages/runar-rs/tests/f297_codegen_conformance.rs` | all 5 fixtures, structural + a real `cargo check` against `runar-lang` as an external dependency |
| Python | `packages/runar-py/tests/test_f297_codegen_conformance.py` | all 5 fixtures, structural + `exec()` of the generated module in a fresh namespace |

No tier's generator fully satisfies MANIFEST.md today: `from_utxo` /
`attach_inscription` (or the language-idiomatic spelling) are missing from
every generator, including the TypeScript reference. Each runner above
documents its own generator's gaps in its module doc comment rather than
asserting them away.

**Zig compile step (N-190).** Zig can't `eval` a string or in-memory-compile
the way the other tiers' runners do, so the compile check lives as a
separate `build.zig` step instead of inside
`sdk_codegen_conformance_test.zig`: `src/sdk_codegen_compile_check_gen.zig`
builds a minimal fixture, calls the real `generateZig`, appends a `test`
block exercising the generated `fromTxId`, and prints the result to stdout;
the `codegen-compile-check` step feeds that back in as a module importing
`"runar-zig"` -> the real SDK and compiles + runs it. `zig build test`
(above) runs it as part of the normal suite. It is this one gap-closer, not
a fifth-fixture structural runner — see the doc comment in that file.

## Running

Each runner is invoked through its host SDK's normal test command:

```sh
cd packages/runar-sdk  && npx vitest run src/__tests__/f297-codegen-conformance.test.ts
cd packages/runar-java && gradle test --tests "*ConformanceTest"
cd packages/runar-rb   && bundle exec rspec spec/sdk/codegen_conformance_spec.rb
cd packages/runar-zig  && zig build test
cd packages/runar-go   && go test ./... -run TestGenerateGo
cd packages/runar-rs   && cargo test --test f297_codegen_conformance
cd packages/runar-py   && python3 -m pytest tests/test_f297_codegen_conformance.py
```

There is intentionally no top-level orchestrator — each SDK ships its
runner inside its own test target so that drift surfaces in the same CI
job that owns the codegen.
