# Ruby Format Design Decisions

**Status:** Pre-implementation
**Date:** 2026-03-07
**Authors:** @sgbett, Claude (Anthropic)

---

## Context

Runar compiles a strict subset of several languages (TypeScript, Go, Rust, Solidity-like, Move-style, Python) into Bitcoin Script. All formats parse into the same `ContractNode` AST, after which the pipeline is identical. This document captures the rationale for adding Ruby as a supported format (`.runar.rb`).

The implementation adds:
- A hand-written parser (tokeniser + recursive descent) in all three compilers (TypeScript, Go, Rust)
- A Ruby gem (`runar-rb`) providing base classes, types, mock crypto, and SDK
- Example contracts, conformance tests, integration tests, and documentation

---

## Key Insight: Types Are Compilation Inputs

The most consequential design decision was how to handle typing. In every other supported format, types are expressed using the host language's native type syntax:

| Format | Property types | Method parameter types |
|--------|---------------|----------------------|
| TypeScript | `readonly pubKeyHash: Addr` | `unlock(sig: Sig, pubKey: PubKey)` |
| Python | `pub_key_hash: Addr` | `def unlock(self, sig: Sig, pub_key: PubKey)` |
| Go | `PubKeyHash runar.Addr` | `func (c *P2PKH) Unlock(sig runar.Sig, ...)` |
| Rust | `pub pub_key_hash: Addr` | `pub fn unlock(&self, sig: &Sig, ...)` |

Ruby has no native type annotations for instance variables or method parameters. This required a design choice.

The critical realisation is that types in Runar are not documentation — they are **compilation inputs that drive code generation**. The stack-lowering pass (pass 5) emits different opcodes depending on property types:

- `bigint` → `OP_NUM2BIN` with 8-byte width
- `boolean` → `OP_NUM2BIN` with 1-byte width
- `ByteString`/`PubKey`/`Sig`/etc. → no conversion (already bytes)

Wrong types produce wrong Bitcoin Script. The type information flows through `PropertyNode.type` and `ParamNode.type` in the AST — both are mandatory fields. The parser must produce them.

---

## Approaches Considered

### 1. YARD Documentation Tags (Rejected for typing)

```ruby
# @return [Addr]
attr_reader :pub_key_hash

# @param sig [Sig]
# @param pub_key [PubKey]
def unlock(sig, pub_key)
```

**Why rejected:**
- Types live in comments — a channel Ruby actively ignores. For something that determines Bitcoin Script correctness, this is the wrong semantic weight.
- Tokenisers normally discard comments. Parsing YARD tags requires a secondary grammar inside comments that no other format parser needs.
- Verbose: each property needs a separate `@return` line; each method parameter needs a separate `@param` line.
- Types feel like documentation rather than code, yet they are compilation-critical.

**YARD is retained for its original purpose** — documenting semantics and behaviour. The DSL handles types; YARD handles the *why*. Never duplicate types in YARD tags.

### 2. Sorbet / `sig` Blocks (Rejected)

```ruby
sig { params(sig: Sig, pub_key: PubKey).void }
def unlock(sig, pub_key)
```

**Why rejected:**
- The Runar parser IS the type enforcer. Sorbet adds a redundant enforcement layer.
- Sorbet's type system (generics, interfaces, flow typing, nil-safety) is vastly over-specified for 13 concrete type names.
- `sorbet-runtime` is a non-trivial dependency for contracts that compile to ~50 bytes of Bitcoin Script.
- `sig {}` blocks are verbose ceremony.
- Sorbet doesn't capture property types on `attr_reader`/`attr_accessor` — you'd still need YARD or a DSL for those.

### 3. Ruby 3 RBS / Steep / Sord (Rejected)

```ruby
# Separate .rbs file:
class P2PKH < Runar::SmartContract
  attr_reader pub_key_hash: Addr
  def unlock: (Sig sig, PubKey pub_key) -> void
end
```

**Why rejected:**
- Types live in a **separate file** (.rbs), breaking the single-file-per-contract convention that every other format follows.
- The Runar parser would need to read and correlate two files per contract.
- Sord generates RBS from YARD — it's an extra layer on top of YARD, not a replacement.
- Steep validates Ruby type safety, not Runar type safety. Different concerns.
- Too many moving parts (YARD → Sord → RBS → Steep) for a 20-line contract.

### 4. Custom Typed Accessors — e.g. `attr_reader_addr` (Rejected)

```ruby
attr_reader_addr :pub_key_hash
attr_accessor_bigint :balance
```

**Why rejected:**
- Doesn't scale: requires one method per type (13+ methods).
- Couples the DSL vocabulary to the type vocabulary.
- Doesn't help with method parameter types at all.
- The right instinct (types in code, not comments) but wrong granularity.

### 5. Custom Lightweight DSL (Chosen)

```ruby
prop :pub_key_hash, Addr

runar_public sig: Sig, pub_key: PubKey
def unlock(sig, pub_key)
```

**Why chosen:**
- **Types are code, not comments.** They live in the code channel and are executed by Ruby at class load time.
- **Free validation from Ruby's constant resolution.** `prop :balance, Bigint` means Ruby resolves `Bigint` as a constant. A typo (`Biigint`) raises `NameError` immediately — before any Runar tooling runs.
- **Idiomatic Ruby pattern.** ActiveRecord, Dry::Struct, Sequel, ROM all use DSL class methods for typed attributes. This IS the Ruby way for domain-specific type declarations.
- **Simplest parser implementation.** `prop` and `runar_public` are standard Ruby expressions that tokenise into predictable token sequences. No comment parsing needed.
- **Concise.** `prop :pub_key_hash, Addr` vs three lines of YARD + attr_reader.
- **Minimal surface area.** Three class methods total: `prop`, `runar_public`, `params`.

---

## The DSL

### Three Class Methods

| Method | Purpose | Ruby internals |
|--------|---------|---------------|
| `prop :name, Type [, readonly: true]` | Declare a typed property | Calls `attr_reader` or `attr_accessor` |
| `runar_public [**param_types]` | Mark next method as public spending entry point, optionally with typed params | Sets visibility flag + stores type hash |
| `params **param_types` | Declare param types for a private method | Stores type hash |

### Visibility Rules

| Scenario | Syntax |
|----------|--------|
| Public, with params | `runar_public sig: Sig, pub_key: PubKey` |
| Public, no params | `runar_public` |
| Private, with params | `params sig: Sig` |
| Private, no params | *(nothing)* |

### Property Readonly Semantics

- In `SmartContract`, all properties are automatically readonly (matches the contract model).
- In `StatefulSmartContract`, properties are mutable by default. Use `readonly: true` for immutable properties.
- This mirrors Ruby's own `attr_reader` (readonly) vs `attr_accessor` (mutable) semantics, with `prop` calling the appropriate one internally.

### Name Conversion

Snake_case Ruby identifiers convert to camelCase in the AST, consistent with the Python format:
- `pub_key_hash` → `pubKeyHash`
- `release_by_seller` → `releaseBySeller`
- `check_sig` → `checkSig`

### YARD Coexistence

YARD documents semantics; the DSL declares types. They do not conflict:

```ruby
# The current token owner's compressed public key.
# Updated on each transfer to the recipient's key.
prop :owner, PubKey
```

Never duplicate types in YARD `@return`/`@param` tags — the DSL is the source of truth.

---

## Contract Syntax Reference

### Stateless

```ruby
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
```

### Stateful

```ruby
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
```

### Stateful with Readonly and Multi-Output

```ruby
require 'runar'

class FungibleToken < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :token_id, ByteString, readonly: true

  def initialize(owner, balance, token_id)
    super(owner, balance, token_id)
    @owner = owner
    @balance = balance
    @token_id = token_id
  end

  runar_public sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint
  def transfer(sig, to, amount, output_satoshis)
    assert check_sig(sig, @owner)
    assert amount > 0
    assert amount <= @balance
    add_output(output_satoshis, to, amount)
    add_output(output_satoshis, @owner, @balance - amount)
  end
end
```

---

## What This Document Is Not

This is not a user guide — see `docs/formats/ruby.md` for that. This captures the *why* behind the design so future contributors (including us) understand the trade-offs that were evaluated and the reasoning that led to the chosen approach.
