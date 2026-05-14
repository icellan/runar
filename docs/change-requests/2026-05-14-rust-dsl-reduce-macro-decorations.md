# Change Request: Reduce Rust DSL macro decorations (`#[methods]`, `#[public]`)

| Field | Value |
|-------|-------|
| **Status** | Proposed — awaiting repository owner approval |
| **Area** | Rust DSL (`.runar.rs`), proc-macros (`runar-rs-macros`), Rust compiler frontend (`parser_rustmacro.rs`) |
| **Authoring context** | Product architecture review against `docs/formats/rust.md` and current compiler implementation |
| **Implementation plan** | [`2026-05-14-rust-dsl-implementation-plan.md`](./2026-05-14-rust-dsl-implementation-plan.md) — phased engineering plan (execute after owner approval) |

---

## Governance and workflow

### Tracking issue

- Open a single **GitHub issue** titled along the lines of: *Rust DSL: remove redundant `#[methods]` / `#[public]` decorations*.
- Paste or link **this document** (`docs/change-requests/2026-05-14-rust-dsl-reduce-macro-decorations.md`) in the issue description as the authoritative proposal.
- The **PR that adds this document** should reference that issue (`Fixes #…` / `Refs #…` per repo convention).
- **All subsequent implementation PRs** should reference the **same issue** so design, approval, and delivery stay traceable.

### Hard blocker

**Implementation work must not merge until explicitly approved by the repository owner.**

This change request may be merged as documentation-only once reviewed, but coding, fixture churn, or macro/API changes remain blocked until owner sign-off is recorded on the tracking issue.

---

## Problem statement

Rust contract authors currently apply decorations at three levels:

1. **Struct**: `#[runar::contract]` or `#[runar::stateful_contract]` — required so `rustc` can strip `#[readonly]` from fields (Rust does not allow custom attribute macros on fields the way we need).
2. **Impl block**: `#[runar::methods(ContractName)]` — must appear before `impl ContractName { … }` or the **Rúnar hand-written `.runar.rs` parser never enters the impl** (the impl is effectively skipped).
3. **Methods**: `#[public]` on spending entry points, and in practice **`pub fn` is typically also present** so tests can call methods from sibling modules.

This creates **felt redundancy** (“decorate the struct, the impl, and every public method”), documentation burden, and a mental model gap: `#[methods]` is not doing semantic lowering in the compiler (it anchors parsing); `#[public]` is largely **duplicating** Rust visibility for methods in the frontend today.

Contributors repeatedly ask whether all three layers are strictly necessary — and whether ergonomics can match “normal Rust impl” (`impl Foo { pub fn … }`) while preserving the exact same AST and script outputs.

---

## Current behavior (facts from codebase)

### Proc-macros (`packages/runar-rs-macros/src/lib.rs`)

- `#[contract]` / `#[stateful_contract]`: strips `#[readonly]` from fields and emits the struct — **semantic for `rustc`**.
- `#[methods(Name)]`: validates shape and emits the impl unchanged — effectively an **identity** macro plus argument validation for the toolchain.
- `#[public]`: passes the method through unchanged — **identity** at macro expansion.

### Frontend parser (`compilers/rust/src/frontend/parser_rustmacro.rs`)

- The tokenizer/parser only collects methods when it sees an attribute that **starts with** `runar::methods`; then it parses `impl … { … }` and walks methods inside.
- For each method it sets visibility to **`Public` if either**:
  - the method carries a `#[public]` attribute **or**
  - the method has Rust `pub` before `fn`.

So **`#[public]` and `pub fn` duplicate the same Rúnar “spending entry” signal** today. Private helpers correspond to **`fn`** without either (or arguably without `#[public]` if authors omit `pub`).

### Documentation (`docs/formats/rust.md`)

- Describes struct attributes, `#[runar::methods(ContractName)]`, and `#[public]` as the normative spelling.
- States that fields should be `pub` for ergonomic native tests — independent of method visibility rules.

---

## Proposal (high level)

### 1. Retain struct-level macros (non-negotiable for now)

Keep **`#[runar::contract]`** / **`#[runar::stateful_contract]`** on the struct. They satisfy the **`rustc`** need to strip field-level `#[readonly]` and preserve a single authoritative contract declaration.

### 2. Remove the need for `#[runar::methods(ContractName)]`

**Desired author experience:**

```rust
#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count += 1;
    }

    fn double(&mut self) {
        self.count *= 2;
    }
}
```

**Semantics (unchanged from today):**

- Any `impl ContractName { … }` block where `ContractName` matches the lone Rúnar contract struct in that file contributes methods to that contract AST.
- If multiple `impl ContractName { … }` blocks appear (Rust allows this), the parser **merges methods** across them in source order unless we explicitly reject splitting (recommended open question below).

Implementation direction: extend `RustDslParser` with a phase that scans for `impl` + ident matching `contract_name`, without requiring a preceding `#`/`runar::methods` sentinel. Optionally keep **`#[runar::methods(T)]` as deprecated no-op for one or more releases** (parser accepts and ignores).

### 3. Drop `#[public]`; encode spending entrypoints with Rust `pub fn`

**Rule:** **`pub fn`** on contract methods ⇒ Rúnar **public / spending entry**; **`fn` (no `pub`)** ⇒ **private helper** (including `init`).

This preserves today’s codegen and validation pipelines because they already consume `Visibility::Public` equivalently regardless of whether it came from `#[public]` or `pub`.

**Deprecation path:**

- Prefer documenting `#[public]` as **obsolete** immediately after approval.
- During migration, optionally keep parser support so old sources still compile, or automate mechanical removal (fixture + example sweep).

---

## Behaviour parity checklist (must remain identical post-change)

The following concerns must be systematically regression-tested against **byte-identical** or **normally accepted** conformance outputs:

| Concern | How we preserve it |
|---------|---------------------|
| **Public vs private methods** | `pub fn` vs `fn` duplicates current `Public`/`Private` split (already partially shared with `#[public]`). |
| **`init`** | Remains **`fn init(&mut self)`** without `pub` ; still stripped and converted into property initializers. |
| **Synthetic constructor** | Unchanged generation from struct fields minus `init` defaults — no dependency on decorators. |
| **Stateful detection** | Still derived from `[readonly]` on fields (`#[contract]` semantics), unchanged. |
| **Multi-public-method dispatch / artifacts** | Only method visibility/name/body AST matters; decorators are not Stack-IR artifacts. |
| **`cargo check` / tests** | `pub` helpers remain callable from `_test.rs`/`#[path]` modules as today. |

---

## Edge cases / design decisions for review

These should be nailed down during owner review or in a brief follow-on design comment on the tracking issue:

1. **Rust restricted visibility**: `pub(crate) fn`, `pub(super) fn`, etc. The tokenizer treats `pub` as a keyword; the current parser consumes a single `pub` token before `fn`. **Today's parser likely does not support `pub(crate) fn`** on contract methods cleanly. Recommendation: formally define **`pub fn` only** as Rúnar-public; constrained `pub(..)` variants are **out of scope** or classified as helpers (`fn`) until explicitly supported.

2. **Multiple contract structs**: Rúnar’s model is **one contract per `.runar.rs` file**. If detection is by name matching between struct and impl, we should **enforce** exactly one annotated contract struct before collecting impl bodies.

3. **Impl ordering vs struct**: Parsing may require two passes — first locate struct + name, second collect matching `impl` blocks — or incremental state while scanning. Behaviour with `impl` before struct (illegal in practice for forward references?) should emit a precise diagnostic.

4. **Macro crates**: Prefer **deprecation** (`#[deprecated]` + doc) on `methods`/`public` in `runar_lang_macros`, rather than abrupt removal, to avoid breaking external users without a semver story.

---

## Deliverables after approval

1. **`compilers/rust`**: Parser changes + unit tests covering impl discovery without `#[methods]`.
2. **Proc-macros / prelude**: Deprecated `methods`/`public`; `docs/formats/rust.md` + README Rust sections updated.
3. **Mechanical churn**: conformance fixtures (`*.runar.rs`), `examples/rust`, and compiler tests relying on decorators.
4. **Semver note**: Crate version bump rationale for `runar-lang-macros` / `runar` if public API or attributes change.
5. **Crates.io-facing documentation** (see next section): README, `Cargo.toml` metadata, rustdoc, and changelog entries aligned with any deprecation or syntax change.

---

## Public crates (`crates.io`) — documentation obligations

The Rust surface is published as three crates (dependency order: compiler → macros → SDK):

| Crates.io name | In-repo path | Role |
|----------------|--------------|------|
| `runar-compiler-rust` | `compilers/rust` | CLI + library compiler |
| `runar-lang-macros` | `packages/runar-rs-macros` | `#[contract]`, `#[methods]`, `#[public]`, … |
| `runar-lang` | `packages/runar-rs` | SDK + prelude (often renamed to `runar` via `package = "runar-lang"` in dependents) |

**Why documentation matters**

- crates.io prominently renders the **crate README** and `Cargo.toml` **description**, **keywords**, **categories**, and links (**repository**, **homepage**). Consumers often never open the repo; the README is the onboarding contract.
- The SDK README explicitly calls out [crates.io layout concerns](../../packages/runar-rs/README.md) (flat TOC, standalone reading). Any DSL ergonomics change should update **`packages/runar-rs/README.md`** (“Writing a Contract”) and **`docs/formats/rust.md`** in the **same delivery unit** so GitHub docs, book-style guides, and the published README stay coherent.
- **Proc-macros** should carry clear **`//!` crate docs** and per-macro **`///` docs** (`packages/runar-rs-macros/src/lib.rs`): what each attribute does, deprecation timeline if applicable, and how it maps to the Rúnar compiler (not “magic” behaviour).
- **Semantic versioning**: Treat observable changes to accepted `.runar.rs` syntax or macro stubs as potentially **minor/major** for `runar-lang-macros` and `runar-lang`, per [API Evolution / Rust semver guidance](https://doc.rust-lang.org/cargo/reference/semver.html). Document the choice in **`CHANGELOG.md`** at the workspace root alongside version bumps (**`scripts/release.sh`** / **`scripts/bump-version.sh`** flow).
- **Optional hardening**: set `readme = "README.md"` explicitly in each crate’s **`Cargo.toml`** if not already present, so crates.io always picks up the intended file when publishing.

**For this change request specifically**

- Update author examples to the new minimal spelling once implemented; keep a short **“migrating from `#[methods]` / `#[public]`”** subsection in the SDK README and in `docs/formats/rust.md`.
- If macros become deprecated no-ops, reflect that in rustdoc with `#[deprecated]` messages pointing to the new style.

---

## Rust testing, CI, and crates.io release mechanics

### What CI already runs (GitHub Actions)

Rust is **not** untested in CI — it is covered in **`.github/workflows/ci.yml`** and related workflows. At a high level:

| Job / step | What it exercises |
|------------|-------------------|
| **`rust-compiler`** | `compilers/rust`: `cargo build --release`, **`cargo test`**. Uploads `runar-compiler-rust` binary for conformance. |
| **`rust-sdk`** | `packages/runar-rs`: **`cargo test`**; **`examples/rust`**: **`cargo test`** (native contract + `compile_check` patterns across the example corpus). |
| **`ts-compiler`** | Builds **`compilers/rust`** for **`pnpm run test`** cross-compiler / vitest matrices that include the Rust toolchain where required. |
| **`conformance`** | Downloads the Rust compiler artifact; IR → hex parity vs other tiers + golden **`expected-script.hex`**; **`--parser-only`** and **`--multi-format`** runner passes (including **`*.runar.rs`** fixtures per `source.json`). |
| **`conformance-anf-parity`** | Builds the Rust ANF driver; parity across SDK interpreters. |
| **`sdk-conformance`** | Builds **`conformance/sdk-output/tools/rs-sdk-tool`**; verifies deploy/script outputs across SDKs including Rust. |
| **`integration`** | **`integration/rust`**: **`cargo test --release -- --ignored`** (regtest + heavier paths), coordinated with other tiers. |

Additional Rust compiler build steps appear in **`.github/workflows/cross-compiler-bytewise.yml`** where relevant.

**Implication for this proposal:** parser or macro changes must keep **`compilers/rust` tests**, **`examples/rust`**, conformance **multi-format** / **parser-only**, and any **`.runar.rs`** fixtures green — that is the existing quality gate before a release.

### How releases reach `crates.io` today

There is **no** GitHub Actions workflow in this repository that automatically runs **`cargo publish`** on tag or `main`. Publishing is a **maintainer-driven, local script** flow:

1. **`scripts/release.sh <version>`** — bumps versions (`scripts/bump-version.sh`), commits, tags (`v*`, Go module tags), pushes, then invokes **`scripts/publish-all.sh`**.
2. **`scripts/publish-all.sh`** — after npm steps, runs **`cargo publish`** in order: **`compilers/rust`** (`runar-compiler-rust`) → **`packages/runar-rs-macros`** → **`packages/runar-rs`**, with waits between publishes for the crates.io index.

**Auth**: `cargo login` (or equivalent token) must be available on the machine running the script; this is **outside** CI by design in the current tree.

### How we “guarantee” behaviour end-to-end

- **Pre-merge / on `main`**: GitHub Actions above provide compiler unit tests, SDK tests, example tests, multi-format conformance, fold-on parity, ANF parity, SDK output conformance, and integration tests. A red `main` should block a release in policy (even though the publish script does not itself invoke CI).
- **At release time**: `release.sh` currently runs **`pnpm run build`** and **`cargo build --release`** for the compiler as a **local** smoke step; it does **not** substitute for the full CI matrix. **Recommendation for maintainers** (can be recorded in release docs): only run **`scripts/publish-all.sh`** after **`main`** (or the release branch) is **green** on GitHub, and consider adding a documented checklist or a future optional **`--dry-run` / `cargo publish --dry-run`** preflight in CI (out of scope for this change request unless the owner wants it).

### Optional follow-up (not part of this CR unless requested)

- Add a **release** or **publish** workflow that triggers on `v*` tags, runs **`cargo publish --dry-run`** (and/or **`cargo package`**) for all three crates, or gates publish on a successful workflow run — to reduce drift between “CI green” and “what actually shipped to crates.io”.

---

## Acceptance criteria

- Author can write idiomatic **`impl ContractName`** without **`#[runar::methods(...)]`**.
- Spending entrypoints are spelled only with **`pub fn`** ; helpers with **`fn`**.
- Existing behaviour (artifacts, ABI, opcode dispatch patterns, stateful injections) unchanged for migrated sources.
- **Owner approval recorded** on the tracking issue prior to merging implementation PRs.
- **Crates.io-facing docs** (`README`, `docs/formats/rust.md`, macro rustdoc, changelog) updated in lockstep with any user-visible syntax or deprecation story.
- **`compilers/rust` `cargo test`**, **`packages/runar-rs` / `examples/rust`**, and conformance jobs that consume **`.runar.rs`** remain passing on CI after implementation.

---

## Open questions for reviewers

1. Preferred migration: **silent backward compatibility** (`#[methods]`/`#[public]` retained as no-ops indefinitely) versus **semver major** cleanup?
2. Should we formally support **multiple `impl ContractName`** blocks merging into one contract?
3. Do we require a **`cargo`-side** procedural assist (e.g. `cargo fix`/lint) or is a documented `sed`/codemod enough?
4. Should **`cargo publish`** remain fully manual via **`scripts/publish-all.sh`**, or should the project add a **tag-gated dry-run/publish** workflow for stronger CD discipline?

---

## References

- `docs/formats/rust.md` — user-facing Rust DSL specification.
- `packages/runar-rs-macros/src/lib.rs` — proc-macro behaviours.
- `compilers/rust/src/frontend/parser_rustmacro.rs` — lexical parser and visibility rules cited above (`runar::methods` gate; `#[public]` **or** `pub` ⇒ public).
- `.github/workflows/ci.yml` — Rust compiler, Rust SDK, conformance, integration jobs.
- `scripts/release.sh`, `scripts/publish-all.sh` — version bump + crates.io publish order for Rust crates.
- `packages/runar-rs/README.md` — crates.io-oriented SDK documentation and installation (`runar-lang` vs `runar`).
- `CHANGELOG.md` — historical note on crates.io releases and scripts.
