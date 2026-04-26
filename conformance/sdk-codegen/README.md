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
├── fixtures/             # shared artifact JSONs
│   ├── p2pkh.json        # stateless + Sig param
│   ├── counter.json      # stateful, mixed terminal/non-terminal
│   └── simple.json       # no constructor params
└── runners/              # per-SDK conformance runners
    ├── java/             # JUnit test that loads fixtures + checks Java codegen
    ├── ruby/             # RSpec spec that loads fixtures + checks Ruby codegen
    └── zig/              # Zig test that loads fixtures + checks Zig codegen
```

The TS/Go/Rust/Python runners are tracked in `RUNAR-SDK-PARITY.md` — they
will be added in follow-up PRs once those SDKs' codegen has tests that
also compile-check generated output. The first three runners shipped here
cover the SDKs whose codegen was extended in the same PR as the
conformance suite.

## Running

Each runner is invoked through its host SDK's normal test command:

```sh
cd packages/runar-java && gradle test --tests "*ConformanceTest"
cd packages/runar-rb   && bundle exec rspec spec/sdk/codegen_conformance_spec.rb
cd packages/runar-zig  && zig build test
```

There is intentionally no top-level orchestrator — each SDK ships its
runner inside its own test target so that drift surfaces in the same CI
job that owns the codegen.
