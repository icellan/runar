# Implementation plan: Reduce Rust DSL macro decorations

| Field | Value |
|-------|-------|
| **Parent change request** | [`2026-05-14-rust-dsl-reduce-macro-decorations.md`](./2026-05-14-rust-dsl-reduce-macro-decorations.md) |
| **Status** | Ready to execute after **repository owner approval** on the tracking issue |
| **Role** | Product architecture — phased delivery plan for engineering |

This plan assumes the CR’s technical direction (struct macros retained; **`impl ContractName`** without **`#[methods]`**; **`pub fn`** vs **`fn`** for public vs private; **`init`** unchanged). Where the CR lists open questions, **recommended defaults** appear below — adjust if owners choose otherwise.

---

## Recommended decisions (defaults for implementers)

| Open question | Recommended default | Rationale |
|---------------|--------------------|-----------|
| Migration style | **Backward compatible for at least one minor release** old spellings parsed (no semver major spike). Deprecate in rustdoc/`#[deprecated]` on stub macros where applicable. |
| Multiple `impl ContractName {}` blocks | **Support merge in source order** (matches rustc’s split-impl ergonomics); **error on duplicate method name** with a clear diagnostic. |
| Codemod | **Mechanical churn in-repo** via scripted replace + **`rustfmt`**; publish a short **migration** section rather than blocking on `cargo fix`. |
| `pub(crate)` / restricted `pub` | **Defer** explicitly; parser continues current behaviour (**single bare `pub` token** ⇒ treat as Rust public keyword read path). Contract authors use **`pub fn`** for entrypoints. |

---

## Preconditions (gates)

1. **Owner sign-off** recorded on the single tracking issue linked from the CR.
2. Confirm **semver policy** with owners: deprecation-only on macros is typically **minor**; removing macro exports or breaking `.runar.rs` without legacy parse path would be **major**.

No implementation merges before precondition 1.

---

## Phase 0 — Traceability & scope lock

**Goal:** Freeze what “done” means and avoid churn.

- [ ] Link this plan from the tracking issue alongside the CR.
- [ ] List target paths: primary touch **`compilers/rust/src/frontend/parser_rustmacro.rs`**, **`packages/runar-rs-macros/src/lib.rs`**, **`examples/rust/**/*.runar.rs`**, conformance **`*.runar.rs`**, **`docs/formats/rust.md`**, **`packages/runar-rs/README.md`**, root **`CHANGELOG.md`**.
- [ ] Optional but useful: add one **fixture** `.runar.rs` that uses *only* the new style (`impl Foo` without `#[methods]`, entrypoints **without** `#[public]`) for regression.

**Exit:** Engineers can open one issue/PR checklist against Phases 1–6 below.

---

## Phase 1 — Parser: discover `impl` without `#[runar::methods]`

**Goal:** Equivalent method list and `Visibility` as today after corpus migration.

### 1.1 Refactor `RustDslParser::parse`

- **Structural change:** Prefer a **two-pass** read over `tokens` with `pos` reset (or checkpoint), so pass (a) parses the contract **`struct`** and **properties** (`contract_name` known), pass (b) collects **every** **`impl CONTRACT_NAME`** method block in file order — including blocks currently reached only via **`#[runar::methods(...)]`** prefix.
- **Unify** logic that walks method items (attributes, **`pub`**, **`fn`**, signature, body) into a helper so **`#[methods]` path and bare `impl`** share one implementation (**DRY**, fewer semantic divergences).

### 1.2 Backward compat during deprecation window

While old sources exist in the wild:

- If **`#[runar::methods(T)]`** immediately precedes **`impl T`**, parse that block exactly as today (**no duplicate ingestion** once unified collection is correct).
- For **`#[public]`:** keep accepting it and mapping to **`Public`** alongside **`pub fn`** until the corpus + docs fully drop it (avoid breaking external crates mid-minor).

### 1.3 Multiple `impl` blocks

- For each **`impl IDENT`** where **`IDENT == contract_name`**, append parsed methods after the prior block’s methods.
- **Duplicate method name:** emit **`Diagnostic::error`** (do not silently overwrite).

### 1.4 Diagnostics & edge cases

- **`impl` before struct:** deterministic error (**“contract struct must be declared before referencing `impl NAME`”** or similar — align with rustc reality where order may still lex).
- **`impl OtherType`:** skip (Rust allows other impls; Rúnar should ignore unrelated blocks or document “only contract impl”).
- Preserve **`init`** extraction and synthetic **constructor** generation unchanged (already post-processes **`methods`** vector).

### 1.5 Unit tests (`compilers/rust`)

Add or extend tests in **`parser_rustmacro.rs`** (existing `#[cfg(test)]` module and/or **`compilers/rust/tests`**) where appropriate:

- [ ] Minimal contract: **`impl Counter { pub fn … / fn … }`** with **no** **`#[methods]`**.
- [ ] Regression: **`#[methods]`** still works; unchanged output vs bare **`impl`** (same snippet, two variants) — normalized comparison on **`ContractNode` methods**: names + visibilities + param counts (or stringify snapshot if project prefers).
- [ ] **`#[public] fn`** private + **`#[public]` only** backward-compat path **if retained**.
- [ ] Two **`impl Foo`** blocks, distinct methods merged in order.
- [ ] Duplicate method name ⇒ error.
- [ ] **`init`** + **`pub fn`** public methods interplay unchanged.

**Exit:** **`cd compilers/rust && cargo test`** green.

---

## Phase 2 — In-repo corpus migration

**Goal:** Teach maintainers dogfood the canonical style; shrink confusion in examples.

Suggested order (**lowest blast radius → highest**):

1. **New-style smoke fixture** under **`compilers/rust`** tests or conformance (if `.runar.rs` present there).
2. **`examples/rust`**: mechanically remove **`#[runar::methods(…)]`** and **`#[public]`** rows where **`pub fn`** already exists; run **`cargo fmt`**; fix any **`#[path]` tests**.
3. **Conformance**: every **`conformance/**/*.runar.rs`** or examples referenced **`source.json` — same mechanical edit **if** parity is unaffected (same IR/hex expectation).
4. **Integration / other `*.runar.rs`** under **`integration/rust`** etc., if any.

Prefer **deterministic scripted edit** (`perl`/`python`/`cargo xtask`-style inline script documented in Phase 6) + manual review for outliers.

**Exit:** **`cd examples/rust && cargo test`** green; conformance + parser-only untouched for tiers not using Rust-format sources (Rust tier still green).

---

## Phase 3 — Proc-macros: deprecation path

**Goal:** crates.io consumers see a clear glide path without surprise breaks.

Files: **`packages/runar-rs-macros/src/lib.rs`**, **`packages/runar-rs/src/prelude.rs`**, crate **`Cargo.toml`** / **`CHANGELOG.md`**.

- [ ] **`#[methods]`**, **`#[public]`**: add **`#[deprecated(note = "...use `pub fn` / plain `impl`...")]`** on the procedural macro stubs **if rustc allows cleanly** on `proc_macro_attribute` (verify on MSRV ~1.70); otherwise **document-only deprecation** in `//!` / `///`.
- [ ] Crate-level **`deprecated`** lint policy: document that external users **should** migrate but old attributes remain expanded as identity shims until next major — **exact policy per owner semver call**.
- [ ] Remove **compile-fail expectations** only if intentionally breaking (usually **defer**).

**Exit:** **`cd packages/runar-rs-macros && cargo test`** (including **`trybuild`** if present).

---

## Phase 4 — Documentation (dual audience: repo + crates.io)

**Goal:** Published README and handbook match behaviour.

Concurrent edits (same PR wave or staged PR):

- [ ] **`docs/formats/rust.md`**: primary syntax **`impl`** + **`pub fn`**; legacy **`#[methods]` / `#[public]`** in a **Migrating from older Rúnar Rust** subsection.
- [ ] **`packages/runar-rs/README.md`**: rewrite **Quick start / Writing a Contract** examples; keep TOC crates.io-safe (see CR).
- [ ] **`examples/rust/function-patterns/FunctionPatterns.runar.rs`** (or similar annotated teaching file): update pedagogical comments.
- [ ] Optional: **`readme = "README.md"`** in **`runar-lang`**, **`runar-lang-macros`**, **`runar-compiler-rust`** `Cargo.toml` files per CR.

**Exit:** Linguist / human review passes; examples copy-pasted from README compile **without** decorators.

---

## Phase 5 — Verification matrix (mandatory CI-equivalent checklist)

Before calling the feature shipped, locally or on CI (**must match `.github/workflows/ci.yml`** intent):

| Check | Command / artefact |
|-------|---------------------|
| Rust compiler tests | **`cd compilers/rust && cargo test`** |
| Rust SDK + examples | **`cd packages/runar-rs && cargo test`** … **`cd examples/rust && cargo test`** |
| Monorepo JS build + tests including cross-compiler | **`pnpm run build`** + **`pnpm run test`** |
| Parser-only conformance | **`conformance/...`** `--parser-only` for Rust tier |
| Multi-format conformance (fold off + fold on parity) | Conformance runner as in CI |

**Regression focus:** Fixture diffs produce **byte-identical** IR/hex versus pre-change for the same nominal contract semantics.

---

## Phase 6 — Release notes & optional automation follow-up

- [ ] **`CHANGELOG.md`**: behavioural change + deprecation with migration pointers.
- [ ] Bump **`semver`** according to Phase 0 policy (likely **minor** if legacy parse stays).
- [ ] **`scripts/release.sh`** / contributor docs: bullet “DSL syntax deprecation — see CHANGELOG”.
- **Out of CR scope but recommended:** CI **`cargo publish --dry-run`** on tag (track separately).

---

## PR slicing suggestion (reviewable batches)

| PR | Contents | Depends on |
|----|----------|------------|
| **PR-A** | Parser + **compilers/rust** tests only; keep **decorators fully valid** path | Approval |
| **PR-B** | Examples + conformance **mechanical migrate** | PR-A merged |
| **PR-C** | Macro deprecation + docs + CHANGELOG version note | PR-B merged (can partially parallel docs with PR-A if clearly marked PRE-CR) |

Smaller commits inside each PR preserve bisect hygiene.

---

## Rollback strategy

- **Parser:** revert **`parser_rustmacro.rs`** and restore corpus in one revert commit.
- **Released crates:** semver **yank** last resort — prefer emitting deprecated macros + parser accepting old syntax (**avoid needing yanks**).

---

## Definition of Done

- Bare **`impl CONTRACT`** without **`#[methods]`** compiles identical AST for migrated contracts as before.
- **`pub fn`** / **`fn`** split matches **`Public` / Private** semantics; **`init`** untouched.
- **CI-equivalent checklist** green.
- **`docs/formats/rust.md`** + **`packages/runar-rs/README.md`** aligned; **CHANGELOG** entry.
- **Owner approval** archived on tracking issue prior to merging **PR-A** onward.
