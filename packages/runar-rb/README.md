# runar-rb

**Write and test Runar Bitcoin Script smart contracts in Ruby.**

The Ruby gem provides base classes, types, a lightweight DSL, mock crypto, real hashes, and EC operations for writing and testing Runar smart contracts natively in Ruby.

---

## Requirements

- Ruby >= 3.0

---

## Installation

```ruby
# Gemfile
gem 'runar-lang'
```

```bash
bundle install
```

Or install directly:

```bash
gem install runar-lang
```

---

## Contract Lifecycle

```
  [1. Write]           Write a contract as a Ruby class extending Runar::SmartContract.
         |
         v
  [2. Test]            Test business logic natively with RSpec (mock crypto).
         |
         v
  [3. Compile]         Compile with any Runar compiler (TS, Go, or Rust) => Bitcoin Script.
         |
         v
  [4. Deploy]          Deploy using any language's SDK.
```

### Writing a Contract

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

### Testing a Contract

```ruby
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

### Stateful Contract

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

### Compiling

Ruby contracts compile through the same pipeline as all other formats. Any Runar compiler works:

```bash
# TypeScript compiler
runar compile MyContract.runar.rb

# Go compiler
runar-go compile MyContract.runar.rb

# Rust compiler
runar-rs compile MyContract.runar.rb
```

---

## The DSL

Ruby has no native type annotations, so Runar provides three class methods:

| Method | Purpose |
|--------|---------|
| `prop :name, Type [, readonly: true]` | Declare a typed property |
| `runar_public [**param_types]` | Mark the next method as a public spending entry point |
| `params **param_types` | Declare parameter types for a private method |

Types are Ruby constants (`Bigint`, `Addr`, `PubKey`, etc.) resolved at class load time. A typo raises `NameError` immediately.

---

## Available Types

`Bigint`, `Int`, `ByteString`, `PubKey`, `Sig`, `Addr`, `Sha256`, `Ripemd160`, `SigHashPreimage`, `RabinSig`, `RabinPubKey`, `Point`

---

## Built-in Functions

**Crypto (mocked):** `check_sig`, `check_multi_sig`, `check_preimage`, `verify_rabin_sig`, `verify_wots`, `verify_slh_dsa_sha2_*`

**Hashes (real):** `hash160`, `hash256`, `sha256`, `ripemd160`

**EC operations (real):** `ec_add`, `ec_mul`, `ec_mul_gen`, `ec_negate`, `ec_on_curve`, `ec_mod_reduce`, `ec_encode_compressed`, `ec_make_point`, `ec_point_x`, `ec_point_y`

**Math:** `safediv`, `safemod`, `within`, `sign_`, `pow_`, `mul_div`, `percent_of`, `sqrt_`, `gcd_`, `divmod_`, `log2_`, `bool_cast`

**Binary:** `num2bin`, `bin2num`, `cat`, `substr`, `left`, `right`, `reverse_bytes`, `len_`

**Preimage:** `extract_locktime`, `extract_output_hash`, `extract_amount`, `extract_version`, `extract_sequence`

**Test helpers:** `mock_sig`, `mock_pub_key`, `mock_preimage`

---

## Testing Guide

Contracts are `.runar.rb` files which are valid Ruby. Require them directly in RSpec:

```ruby
require_relative 'MyContract.runar'
```

All built-in functions are available at the top level (mixed into `Kernel`). Mock crypto functions always return `true`, so tests focus on business logic. Hash functions use real `digest`/`openssl` implementations.

```bash
cd examples/ruby && bundle exec rspec
```

---

## Dependencies

Zero external dependencies. Uses Ruby stdlib only (`digest`, `openssl`).

---

## Design

See [DESIGN.md](./DESIGN.md) for the full rationale behind the DSL approach, including alternatives that were considered and rejected (YARD, Sorbet, RBS, custom typed accessors).
