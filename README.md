# Rúnar

*Old Norse plural for "runes" (rún = secret/script/mystery). Pronounced ROO-nar.*

**Write Bitcoin smart contracts in TypeScript, Go, Rust, Ruby, Python, Zig, Solidity, or Move. Compile to Bitcoin Script.**

<!-- Badges -->
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![npm version](https://img.shields.io/badge/npm-v0.3.2-orange)

---

## Write Once, Compile Anywhere

Rúnar lets you write Bitcoin SV smart contracts in the language you already know. All formats compile through the same pipeline and produce identical Bitcoin Script.

<table>
<tr>
<td>

**TypeScript**
```typescript
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
```
</td>
<td>

**Go**
```go
type P2PKH struct {
    runar.SmartContract
    PubKeyHash runar.Addr `runar:"readonly"`
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
```
</td>
</tr>
<tr>
<td>

**Rust**
```rust
#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
```
</td>
<td>

**Solidity-like**
```solidity
pragma runar ^0.1.0;

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
```
</td>
</tr>
<tr>
<td>

**Ruby**
```ruby
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
</td>
<td>

**Python**
```python
from runar import (SmartContract, Addr, PubKey,
    Sig, hash160, check_sig, assert_, public)

class P2PKH(SmartContract):
    pub_key_hash: Addr

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
```
</td>
</tr>
<tr>
<td colspan="2">

**Move-style**
```move
module P2PKH {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    resource struct P2PKH {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}
```
</td>
</tr>
</table>

**Zig**
```zig
const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pub_key_hash: runar.Addr,

    pub fn init(pub_key_hash: runar.Addr) P2PKH {
        return .{ .pub_key_hash = pub_key_hash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
        runar.assert(runar.hash160(pub_key) == self.pub_key_hash);
        runar.assert(runar.checkSig(sig, pub_key));
    }
};
```

All eight formats produce the same Bitcoin Script: `OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`

---

## Why Rúnar?

Bitcoin Script development today forces a choice between hand-writing opcodes (error-prone, unauditable) or adopting a framework with heavy decorator-based DSLs that obscure what happens on-chain. Rúnar takes a different path:

- **No decorators** — uses native language keywords (`readonly`, `public`, `immutable`, `#[readonly]`, `prop`)
- **Write in your language** — TypeScript, Go, Rust, Ruby, Python, Zig, Solidity-like, or Move-style
- **Test natively** — `vitest` for TS, `go test` for Go, `cargo test` for Rust, `rspec` for Ruby, `pytest` for Python, `zig build test` for Zig examples
- **Five compilers** — TypeScript (reference), Go, Rust, Python, Zig — all produce byte-identical output
- **Post-quantum ready** — WOTS+ and SLH-DSA (FIPS 205) signature verification in Bitcoin Script
- **Nanopass architecture** — 6 small passes, each auditable in a single sitting
- **Full IDE support** — type checking, autocompletion, go-to-definition in every language

---

## Quick Start

### TypeScript

```bash
pnpm add runar-lang runar-compiler runar-cli
runar compile MyContract.runar.ts    # => artifacts/MyContract.runar.json
```

### Go

```bash
# In your go.mod, add:
#   require github.com/icellan/runar/packages/runar-go v0.1.0
# Contracts are real Go — test with go test, compile with the Rúnar Go compiler
go test ./...
```

### Rust

```bash
# In Cargo.toml: runar = { package = "runar-lang", version = "0.1.0" }
# Contracts are real Rust — test with cargo test, compile with the Rúnar Rust compiler
cargo test
```

### Ruby

```bash
# In Gemfile: gem 'runar-lang'
# Contracts are real Ruby — test with rspec, compile with any Rúnar compiler
bundle exec rspec
```

### Python

```bash
# pip install runar-lang
# Contracts are real Python — test with pytest, compile with any Rúnar compiler
PYTHONPATH=packages/runar-py python3 -m pytest
```

### Zig

```bash
cd examples/zig && zig build test
cd ../..
cd compilers/zig && zig build run -- compile ../../examples/zig/p2pkh/P2PKH.runar.zig
```

---

## Test Your Contracts

The maintained frontends all have native test workflows. Go, Rust, and Python tests execute contract logic directly in the host language; Zig example tests live next to the contracts and combine compile checks, direct contract execution where the current Zig surface supports it, and Zig-native helper/runtime tests.

**TypeScript** (vitest):
```typescript
import { TestContract } from 'runar-testing';

const counter = TestContract.fromSource(source, { count: 0n });
counter.call('increment');
expect(counter.state.count).toBe(1n);
```

**Go** (go test):
```go
func TestCounter_Increment(t *testing.T) {
    c := &Counter{Count: 0}
    c.Increment()
    if c.Count != 1 { t.Errorf("expected 1, got %d", c.Count) }
}

func TestCounter_Compile(t *testing.T) {
    if err := runar.CompileCheck("Counter.runar.go"); err != nil {
        t.Fatalf("Rúnar compile check failed: %v", err)
    }
}
```

**Rust** (cargo test):
```rust
#[path = "Counter.runar.rs"]
mod contract;
use contract::*;

#[test]
fn test_increment() {
    let mut c = Counter { count: 0 };
    c.increment();
    assert_eq!(c.count, 1);
}

#[test]
fn test_compile() {
    runar::compile_check(include_str!("Counter.runar.rs"), "Counter.runar.rs").unwrap();
}
```

**Ruby** (rspec):
```ruby
require_relative 'Counter.runar'

RSpec.describe Counter do
  it 'increments' do
    c = Counter.new(0)
    c.increment
    expect(c.count).to eq(1)
  end

  it 'fails to decrement at zero' do
    c = Counter.new(0)
    expect { c.decrement }.to raise_error(RuntimeError)
  end
end
```

**Python** (pytest):
```python
from conftest import load_contract
from runar import hash160, mock_sig, mock_pub_key

contract_mod = load_contract("P2PKH.runar.py")
P2PKH = contract_mod.P2PKH

def test_unlock():
    pk = mock_pub_key()
    c = P2PKH(pub_key_hash=hash160(pk))
    c.unlock(mock_sig(), pk)
```

**Zig** (`zig build test`):
```bash
cd examples/zig
zig build test
```

Zig example tests live next to the contracts under `examples/zig/` and use `packages/runar-zig` for compile checks, fixtures, direct-execution coverage on simpler contracts, and native helper/runtime coverage.

---

## Supported Formats

| Format | Extension | Compilers | IDE Support | Status |
|--------|-----------|-----------|-------------|--------|
| TypeScript | `.runar.ts` | TS, Go, Rust, Python, Zig | Full (`tsc`) | **Stable** |
| Zig | `.runar.zig` | TS, Zig | Full (`zls`) | Experimental |
| Go | `.runar.go` | Go, Python | Full (`gopls`) | Experimental |
| Rust DSL | `.runar.rs` | Rust, Python | Full (`rust-analyzer`) | Experimental |
| Ruby | `.runar.rb` | TS, Go, Rust, Python | Full (Ruby LSP) | Experimental |
| Python | `.runar.py` | TS, Go, Rust, Python | Full (`pyright`) | Experimental |
| Solidity-like | `.runar.sol` | TS, Go, Rust, Python | Syntax highlighting | Experimental |
| Move-style | `.runar.move` | TS, Go, Rust, Python | Syntax highlighting | Experimental |

All formats parse into the same `ContractNode` AST. From there, the pipeline is identical:

```
  .runar.ts ──┐
  .runar.zig ──┤
  .runar.sol ──┤
  .runar.move ─┤
  .runar.py ───┼──► ContractNode AST ──► Validate ──► TypeCheck ──► ANF ──► Stack ──► Bitcoin Script
  .runar.rb ───┤
  .runar.go ───┤
  .runar.rs ───┘
```

---

## Example Contracts

21 example contracts demonstrate the major contract patterns implemented across the maintained native-language frontends:

| Contract | Pattern | Stateful | Multi-method |
|----------|---------|----------|-------------|
| [P2PKH](examples/ts/p2pkh/) | Pay-to-Public-Key-Hash | No | No |
| [Escrow](examples/ts/escrow/) | Multi-party authorization | No | Yes (4 paths) |
| [Counter](examples/ts/stateful-counter/) | Stateful state machine | Yes | Yes |
| [Auction](examples/ts/auction/) | Bidding with deadline | Yes | Yes |
| [CovenantVault](examples/ts/covenant-vault/) | Spending constraints | No | No |
| [OraclePriceFeed](examples/ts/oracle-price/) | Rabin signature oracle | No | No |
| [FungibleToken](examples/ts/token-ft/) | Token with split/merge | Yes | Yes (3 paths) |
| [SimpleNFT](examples/ts/token-nft/) | NFT with transfer/burn | Yes | Yes |
| [PostQuantumWallet](examples/ts/post-quantum-wallet/) | WOTS+ signature verification | No | No |
| [SPHINCSWallet](examples/ts/sphincs-wallet/) | SLH-DSA (FIPS 205) verification | No | No |
| [SchnorrZKP](examples/ts/schnorr-zkp/) | Schnorr zero-knowledge proof (EC ops) | No | No |
| [FunctionPatterns](examples/ts/function-patterns/) | Public/private methods, built-ins | Yes | Yes |
| [MathDemo](examples/ts/math-demo/) | Math built-in functions | Yes | Yes |
| [ConvergenceProof](examples/ts/convergence-proof/) | Convergence proof pattern | No | No |
| [ECDemo](examples/ts/ec-demo/) | EC point operations | No | No |
| [BoundedCounter](examples/ts/property-initializers/) | Property initializers with defaults | Yes | Yes |
| [P2Blake3PKH](examples/ts/p2blake3pkh/) | BLAKE3-based pay-to-hash | No | No |
| [TicTacToe](examples/ts/tic-tac-toe/) | Stateful game logic | Yes | Yes |
| [Blake3Test](examples/ts/blake3/) | BLAKE3 compression/hash built-ins | No | No |
| [Sha256CompressTest](examples/ts/sha256-compress/) | SHA-256 compression builtin | No | No |
| [Sha256FinalizeTest](examples/ts/sha256-finalize/) | SHA-256 finalize builtin | No | No |

All 21 examples are available in `ts/`, `go/`, `rust/`, `python/`, and `zig/`. 11 contracts are available in all 8 formats (TypeScript, Go, Rust, Ruby, Python, Zig, Solidity, Move). FunctionPatterns, PostQuantumWallet, SPHINCSWallet, SchnorrZKP, and ConvergenceProof are available in TypeScript, Go, Rust, Ruby, and Python. A 16-contract subset is also available in `sol/` and `move/`.
```
examples/
  ts/p2pkh/          P2PKH.runar.ts + P2PKH.test.ts
  zig/p2pkh/         P2PKH.runar.zig + P2PKH_test.zig
  go/p2pkh/          P2PKH.runar.go + P2PKH_test.go
  rust/p2pkh/        P2PKH.runar.rs + P2PKH_test.rs
  ruby/p2pkh/        P2PKH.runar.rb + p2pkh_spec.rb
  python/p2pkh/      P2PKH.runar.py + test_p2pkh.py
  sol/p2pkh/         P2PKH.runar.sol + P2PKH.test.ts
  move/p2pkh/        P2PKH.runar.move + P2PKH.test.ts
```

The Zig example tree is backed by `packages/runar-zig` and a shared runner at `examples/zig/examples_test.zig`.

---

## Architecture

### Compilation Pipeline

The compiler is structured as six small, composable nanopass transforms. Each pass does one thing, transforms one IR into the next, and is small enough to audit in a single sitting.

| Pass | Name | Input | Output |
|------|------|-------|--------|
| 1 | **Parse** | Source (any format) | Rúnar AST |
| 2 | **Validate** | Rúnar AST | Validated AST |
| 3 | **Type-check** | Validated AST | Typed AST |
| 4 | **ANF Lower** | Typed AST | ANF IR |
| 5 | **Stack Lower** | ANF IR | Stack IR |
| 6 | **Emit** | Stack IR | Bitcoin Script |

The constant folding optimizer (+ dead binding elimination) is available between passes 4 and 5 but is disabled by default to preserve ANF conformance. The peephole optimizer runs between passes 5 and 6 (always enabled).

### Multi-Compiler Strategy

Rúnar defines a **canonical IR conformance boundary** at the ANF level. Any compiler that produces byte-identical ANF IR for a given source file is conformant:

- The **TypeScript compiler** is the reference implementation
- The **Go compiler** produces identical output for all example contracts including post-quantum
- The **Rust compiler** produces identical output for all example contracts including post-quantum
- The **Python compiler** produces identical output for all example contracts including post-quantum
- The **Zig compiler** produces identical output for the conformance suite and benchmarked example workloads

The conformance suite in `conformance/` contains 27 golden-file tests (including WOTS+, SLH-DSA, SHA-256, BLAKE3, and EC primitives). The maintained compilers target the same suite.

### Contract Model

- `SmartContract` — stateless, all properties `readonly`
- `StatefulSmartContract` — mutable state carried across transactions via OP_PUSH_TX
- `this.addOutput(satoshis, ...values)` — multi-output intrinsic for token splitting/merging
- Only Rúnar built-in functions are allowed — the compiler rejects arbitrary function calls

### Language Subset

Only a strict subset of each language is valid Rúnar. The compiler enforces this at parse, validate, and typecheck time:

**Allowed:** Class/struct declarations, readonly/mutable properties, public/private methods, const/let variables, if/else, bounded for loops, arithmetic/comparison/logical/bitwise operators, ternary expressions, Rúnar built-in function calls.

**Disallowed:** Unbounded loops, recursion, async/await, closures, exceptions, dynamic arrays, arbitrary function calls (`Math.floor`, `console.log`, etc.).

---

## Project Structure

```
packages/
  runar-lang/          # Language types and builtins (developer imports)
  runar-compiler/      # TypeScript compiler (6 nanopass passes)
  runar-ir-schema/     # Shared IR type definitions and JSON schemas
  runar-testing/       # TestContract API, Script VM, interpreter, fuzzer
  runar-sdk/           # Deployment SDK (providers, signers)
  runar-cli/           # CLI tool
  runar-go/            # Go package: types, mock crypto, real hashes, CompileCheck(), deployment SDK
  runar-rb/            # Ruby gem: types, DSL, mock crypto, real hashes, EC operations, deployment SDK
  runar-rs/            # Rust crate: prelude types, mock crypto, real hashes, compile_check(), deployment SDK
  runar-rs-macros/     # Rust proc-macros (#[runar::contract], #[public], etc.)
  runar-py/            # Python package: types, mock crypto, real hashes, deployment SDK
  runar-zig/           # Zig package: native testing/runtime helpers and compile checks
compilers/
  go/                 # Go compiler (tree-sitter + native Go frontend)
  rust/               # Rust compiler (SWC + native Rust frontend)
  python/             # Python compiler (native Python frontend)
  zig/                # Zig compiler (native Zig + TypeScript frontends)
conformance/          # Cross-compiler conformance test suite
examples/
  ts/                 # TypeScript contracts + tests
  go/                 # Go contracts + tests
  rust/               # Rust contracts + tests
  ruby/               # Ruby contracts + tests
  python/             # Python contracts + tests
  sol/                # Solidity-like contracts + tests
  move/               # Move-style contracts + tests
  zig/                # Zig contracts + adjacent Zig tests
  sdk-usage/          # SDK usage reference docs (not runnable)
end2end-example/      # End-to-end example (ts, go, rust, sol, move, webapp, webapp-blackjack)
spec/                 # Language specification
docs/                 # Documentation + format guides
```

---

## Development

### Prerequisites

- **Node.js** >= 20, **pnpm** 9.15+
- **Go** 1.26+ (for Go compiler and Go contract tests)
- **Rust** 1.75+ (for Rust compiler and Rust contract tests)
- **Ruby** 3.0+ (optional, for Ruby contract tests)
- **Python** 3.10+ (for Python compiler and Python contract tests)

### Build & Test

```bash
git clone https://github.com/icellan/runar.git && cd runar
pnpm install && pnpm build

# TypeScript (packages + all format examples)
npx vitest run

# Go compiler + Go contract tests
cd compilers/go && go test ./...
cd examples/go && go test ./...

# Rust compiler + Rust contract tests
cd compilers/rust && cargo test
cd examples/rust && cargo test

# Ruby contract tests
cd examples/ruby && bundle exec rspec

# Python package + Python contract tests
cd packages/runar-py && python3 -m pytest
cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest
```

---

## Academic Foundations

| Technique | Reference | Used In |
|-----------|-----------|---------|
| Nanopass compilation | Sarkar, Waddell & Dybvig (ICFP 2004) | 6-pass pipeline architecture |
| Administrative Normal Form | Flanagan, Sabry, Duba & Felleisen (PLDI 1993) | IR between typed AST and stack machine |
| Affine types | Walker (2005), Move language (2019) | Compile-time resource safety |
| Definitional interpreter | Reynolds (1972), Amin & Rompf (POPL 2017) | Reference interpreter oracle |
| Differential testing | Yang, Chen, Eide & Regehr (PLDI 2011, CSmith) | Cross-compiler fuzzing |
| Stack scheduling | Koopman (1989) | ANF → Bitcoin Script stack mapping |

---

## License

MIT
