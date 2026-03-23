# Ruby Contract Format

**Status:** Experimental
**File extension:** `.runar.rb`
**Supported compilers:** TypeScript, Go, Rust, Python (all four)

---

## Overview

The Ruby format lets you write Runar contracts as Ruby classes extending `Runar::SmartContract` or `Runar::StatefulSmartContract`. Contracts use a lightweight DSL — `prop` for typed properties, `runar_public` for public method visibility, and `params` for private method parameter types. Instance variables use `@var` syntax.

All four compilers (TypeScript, Go, Rust, Python) support `.runar.rb` parsing, so Ruby-format contracts produce identical Bitcoin Script across all compilers.

---

## Syntax

### Imports

```ruby
require 'runar'
```

The `require 'runar'` line is consumed by the parser but does not affect compilation. All Runar types and built-in functions are available regardless.

### Class Declaration

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

- Extend `Runar::SmartContract` (stateless) or `Runar::StatefulSmartContract` (stateful)
- One contract class per file
- Constructor must call `super(...)` as the first statement

### Properties

Properties are declared with the `prop` class method, which provides type information to the compiler:

```ruby
class Auction < Runar::StatefulSmartContract
  prop :auctioneer, PubKey, readonly: true    # immutable
  prop :highest_bidder, PubKey                # mutable (stateful)
  prop :highest_bid, Bigint                   # mutable (stateful)
  prop :deadline, Bigint, readonly: true      # immutable
```

- In `SmartContract`, all properties are automatically readonly
- In `StatefulSmartContract`, properties are mutable by default. Use `readonly: true` for immutable properties
- `prop` calls `attr_reader` (readonly) or `attr_accessor` (mutable) internally
- Properties are accessed as `@var` (instance variables), not `self.var`

### Method Visibility

| Ruby syntax | Runar visibility |
|------------|-----------------|
| `runar_public` before `def` | `public` (spending entry point) |
| `params` before `def` | `private` (inlined helper, with typed params) |
| No annotation | `private` (inlined helper, no params) |

```ruby
# Public method with typed params
runar_public sig: Sig, pub_key: PubKey
def unlock(sig, pub_key)
  ...
end

# Public method with no params
runar_public
def increment
  ...
end

# Private method with typed params
params a: Bigint, b: Bigint
def compute_threshold(a, b)
  a * b + 1
end
```

### Name Conversion

All Ruby snake_case identifiers are converted to camelCase in the AST:

| Ruby | AST |
|------|-----|
| `pub_key_hash` | `pubKeyHash` |
| `highest_bid` | `highestBid` |
| `check_sig` | `checkSig` |
| `extract_locktime` | `extractLocktime` |
| `ec_mul_gen` | `ecMulGen` |

Special cases:
- `initialize` becomes the constructor
- `@prop` becomes `this.prop`
- `verify_wots` maps to `verifyWOTS` (not `verifyWots`)
- All SLH-DSA variants have explicit mappings (e.g., `verify_slh_dsa_sha2_128s` → `verifySLHDSA_SHA2_128s`)

### Property Access

Ruby contracts use instance variables (`@var`) to access properties:

```ruby
assert hash160(pub_key) == @pub_key_hash    # reads property
@count += 1                                  # mutates property (stateful)
@highest_bidder = bidder                     # assigns property (stateful)
```

---

## Type Mappings

| Ruby Type | Runar AST Type |
|-----------|---------------|
| `Bigint` / `Integer` / `Int` | `bigint` |
| `Boolean` | `boolean` |
| `ByteString` | `ByteString` |
| `PubKey` | `PubKey` |
| `Sig` | `Sig` |
| `Addr` | `Addr` |
| `Sha256` | `Sha256` |
| `Ripemd160` | `Ripemd160` |
| `SigHashPreimage` | `SigHashPreimage` |
| `RabinSig` | `RabinSig` |
| `RabinPubKey` | `RabinPubKey` |
| `Point` | `Point` |
| `readonly: true` | Marks property `readonly: true` |

Types are Ruby constants resolved at class load time. A typo (`Biigint`) raises `NameError` immediately — before any Runar tooling runs.

---

## Operators

| Ruby | AST / Bitcoin Script |
|------|---------------------|
| `==` / `!=` | `===` / `!==` (strict equality) |
| `**` | `pow()` call |
| `&&` / `\|\|` / `!` | `&&` / `\|\|` / `!` |
| `<<` / `>>` | `OP_LSHIFT` / `OP_RSHIFT` |
| `x ? a : b` | ternary expression |

---

## Assertions

Ruby contracts use the `assert` keyword (no parentheses required):

```ruby
assert check_sig(sig, pub_key)
assert amount > 0
assert hash160(pub_key) == @pub_key_hash
```

Compiles to the same AST as all other formats: `CallExpr { callee: "assert", args: [...] }`.

---

## Loops

Only bounded `for` loops are supported, using Ruby's range syntax:

```ruby
for i in 0...5         # i = 0, 1, 2, 3, 4  (exclusive upper bound)
  ...
end

for i in 0..4          # i = 0, 1, 2, 3, 4  (inclusive upper bound)
  ...
end

for i in a...b do      # 'do' keyword is optional
  ...
end
```

---

## Byte Literals

```ruby
data = 'deadbeef'                  # single-quoted hex byte string
hash = "cafebabe"                  # double-quoted also works
```

---

## Examples

### Stateless Contract (P2PKH)

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

### Stateful Contract (Counter)

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

### EC Operations (Schnorr ZKP)

```ruby
require 'runar'

class SchnorrZKP < Runar::SmartContract
  prop :pub_key, Point

  def initialize(pub_key)
    super(pub_key)
    @pub_key = pub_key
  end

  runar_public r_point: Point, s: Bigint, e: Bigint
  def verify(r_point, s, e)
    assert ec_on_curve(r_point)
    s_g = ec_mul_gen(s)
    e_p = ec_mul(@pub_key, e)
    rhs = ec_add(r_point, e_p)
    assert ec_point_x(s_g) == ec_point_x(rhs)
    assert ec_point_y(s_g) == ec_point_y(rhs)
  end
end
```

---

## Testing Ruby Contracts

Ruby contracts are tested natively using RSpec with the `runar` gem:

```ruby
require_relative '../spec_helper'
require_relative 'P2PKH.runar'

RSpec.describe P2PKH do
  it 'unlocks with valid signature' do
    pk = mock_pub_key
    c = P2PKH.new(hash160(pk))
    expect { c.unlock(mock_sig, pk) }.not_to raise_error
  end

  it 'fails with wrong public key' do
    pk = mock_pub_key
    wrong_pk = '03' + '00' * 32
    c = P2PKH.new(hash160(pk))
    expect { c.unlock(mock_sig, wrong_pk) }.to raise_error(RuntimeError)
  end
end
```

Mock crypto functions (`check_sig`, `check_preimage`, `verify_wots`, etc.) always return `true` for business logic testing. Hash functions (`hash160`, `sha256`, etc.) use real implementations via `digest` and `openssl`.

---

## Runtime Package

The `runar-lang` gem (`packages/runar-rb/`) provides:

- **Types**: `Bigint`, `ByteString`, `PubKey`, `Sig`, `Addr`, `Point`, etc. (Ruby constants)
- **Base classes**: `Runar::SmartContract`, `Runar::StatefulSmartContract`
- **DSL methods**: `prop`, `runar_public`, `params`
- **Mock crypto**: `check_sig`, `check_preimage`, `verify_wots`, `verify_slh_dsa_*` (always return true)
- **Real hashes**: `hash160`, `hash256`, `sha256`, `ripemd160` (via `digest`/`openssl`)
- **Real EC**: `ec_add`, `ec_mul`, `ec_mul_gen`, `ec_negate`, `ec_on_curve`, etc. (pure Ruby secp256k1)
- **Math**: `safediv`, `sqrt_`, `gcd_`, `clamp`, `sign_`, `pow_`, `mul_div`, `percent_of`, `log2_`

Zero external dependencies. EC operations use pure Ruby integer arithmetic with secp256k1 curve parameters.

---

## IDE Support (Ruby LSP)

The `runar-lang` gem includes a built-in [Ruby LSP](https://shopify.github.io/ruby-lsp/) addon that provides IDE features for `.runar.rb` contract files:

- **Hover documentation** for builtin functions (`sha256`, `check_sig`, `pow`, etc.), type constants (`Bigint`, `ByteString`, etc.), and DSL methods (`prop`, `runar_public`, `params`)
- **Autocompletion** for type constants and builtin function names
- **Go-to-definition** for properties declared with `prop`
- **Instance variable indexing** — `prop :count, Bigint` teaches the LSP that `@count` exists

### Setup

1. Add `runar-lang` to your project's `Gemfile`:
   ```ruby
   gem 'runar-lang', path: 'packages/runar-rb'
   ```
2. Install the [Ruby LSP extension](https://marketplace.visualstudio.com/items?itemName=Shopify.ruby-lsp) in VS Code
3. Run `bundle install` — the addon is discovered automatically

The addon only activates for files ending in `.runar.rb`, so it won't interfere with regular Ruby code in the same project.

---

## Design Rationale

Ruby has no native type annotations for instance variables or method parameters. The `prop`/`runar_public`/`params` DSL was chosen over alternatives (YARD tags, Sorbet, RBS) because types in Runar are **compilation inputs that drive code generation**, not documentation. The DSL keeps types in the code channel where Ruby's constant resolution provides free validation (a typo raises `NameError` immediately).

See `packages/runar-rb/DESIGN.md` for the full design rationale.
