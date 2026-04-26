# runar-java

Java runtime and deployment SDK for the Rúnar TypeScript-to-Bitcoin Script
compiler. Compiles, deploys, and calls compiled Rúnar contracts against
Bitcoin SV (BSV) — mainnet, testnet, regtest, or a mocked in-memory
provider — from a JDK 17+ application.

This is the Java sibling of `runar-sdk` (TS), `runar-go` (Go), `runar-rs`
(Rust), `runar-py` (Python), `runar-zig` (Zig), and `runar-rb` (Ruby).
All seven SDKs produce byte-identical deployed locking scripts for the
same compiled artifact and constructor args
(see `conformance/sdk-output/`).

## 2. Table of contents

3. [Installation](#3-installation)
4. [Quick start](#4-quick-start)
5. [Core concepts](#5-core-concepts)
6. [Writing a contract](#6-writing-a-contract)
7. [Compiling](#7-compiling)
8. [Deploying contracts](#8-deploying-contracts)
9. [Calling contract methods](#9-calling-contract-methods)
   - [9a. Single-signer (`call`)](#9a-single-signer-call)
   - [9b. Multi-signer (`prepareCall` / `finalizeCall`)](#9b-multi-signer-preparecall--finalizecall)
   - [9c. BRC-100 wallet signing (`WalletProvider`)](#9c-brc-100-wallet-signing-walletprovider)
10. [Stateful contracts](#10-stateful-contracts)
11. [UTXO and fee management](#11-utxo-and-fee-management)
12. [Typed contract bindings](#12-typed-contract-bindings)
13. [Testing](#13-testing)
    - [13a. Off-chain testing](#13a-off-chain-testing)
    - [13b. Integration testing against a regtest node](#13b-integration-testing-against-a-regtest-node)
14. [Provider configuration](#14-provider-configuration)
15. [Full API reference](#15-full-api-reference)
16. [Error handling](#16-error-handling)
17. [Troubleshooting / FAQ](#17-troubleshooting--faq)
18. [Versioning and stability](#18-versioning-and-stability)
19. [Links](#19-links)

---

## 3. Installation

The artifacts are published as `build.runar:runar-java`. Add to a Gradle
Kotlin DSL build:

```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("build.runar:runar-java:0.4.4")
}
```

Or with the Groovy DSL:

```groovy
dependencies {
    implementation 'build.runar:runar-java:0.4.4'
}
```

For a Maven build:

```xml
<dependency>
    <groupId>build.runar</groupId>
    <artifactId>runar-java</artifactId>
    <version>0.4.4</version>
</dependency>
```

### Requirements

- **JDK 17** (compile target). JDK 21 LTS recommended for development.
- **Gradle 8.5+** when building from source.
- **BouncyCastle (`bcprov-jdk18on:1.78`)** is pulled in transitively and
  provides ECDSA + RIPEMD-160 + DER encoding.

The SDK also depends on the frontend-only `build.runar:runar-java-compiler`
artifact so [`CompileCheck`](src/main/java/runar/lang/sdk/CompileCheck.java)
can run parse → validate → typecheck without shelling out to a separate
compiler binary. In a multi-module repo the dev build composite-includes
`compilers/java` via `settings.gradle.kts`; consumers of the published
artifact get the compiler frontend as a transitive Maven dependency.

### Verifying the install

```java
import runar.lang.sdk.CompileCheck;
import java.nio.file.Path;

public class CheckInstall {
    public static void main(String[] args) throws Exception {
        CompileCheck.run(Path.of("MyContract.runar.java"));
        System.out.println("runar-java is wired up");
    }
}
```

---

## 4. Quick start

The smallest end-to-end loop: a stateful `Counter` contract, a
`MockProvider` for an in-memory chain, a `MockSigner` for non-cryptographic
signing, a deploy, a call, and a state read.

### The contract — `Counter.runar.java`

[`examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java`](../../examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java):

```java
package runar.examples.statefulcounter;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class Counter extends StatefulSmartContract {

    Bigint count; // mutable state — persists across spending transactions

    Counter(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        this.count = this.count.plus(Bigint.ONE);
    }

    @Public
    void decrement() {
        assertThat(this.count.gt(Bigint.ZERO));
        this.count = this.count.minus(Bigint.ONE);
    }
}
```

### Compile, deploy, call

```java
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import runar.lang.sdk.CompileCheck;
import runar.lang.sdk.LocalSigner;
import runar.lang.sdk.MockProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;
import runar.lang.sdk.UTXO;

public class QuickStart {
    public static void main(String[] args) throws Exception {
        // 1. Validate the source compiles.
        Path source = Path.of("Counter.runar.java");
        CompileCheck.run(source);

        // 2. Load the compiled artifact (produced by the runar CLI).
        RunarArtifact artifact = RunarArtifact.fromJson(
            Files.readString(Path.of("Counter.runar.json")));

        // 3. Wire up provider + signer.
        MockProvider provider = new MockProvider("regtest");
        LocalSigner signer = new LocalSigner(
            "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725");
        provider.addUtxo(signer.address(),
            new UTXO("a".repeat(64), 0, 100_000_000L, "76a914" + "00".repeat(20) + "88ac"));

        // 4. Construct + deploy.
        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO));
        RunarContract.DeployOutcome deploy =
            contract.deploy(provider, signer, 5_000L);
        System.out.println("deployed: " + deploy.txid());

        // 5. Call increment, then read updated state.
        RunarContract.CallOutcome call = contract.call(
            "increment", List.of(), null, provider, signer);
        System.out.println("call txid: " + call.txid());
        System.out.println("count   = " + contract.state("count"));
        // count = 1
    }
}
```

For a real on-chain run, swap `MockProvider` for `RPCProvider`,
`WhatsOnChainProvider`, or `GorillaPoolProvider` — the rest is unchanged.

---

## 5. Core concepts

The SDK has eight first-class abstractions; each is a single Java type
plus its implementations.

### Artifact — [`RunarArtifact`](src/main/java/runar/lang/sdk/RunarArtifact.java)

The compiled contract. An immutable `record` holding the locking-script
template, ABI (constructor + methods + param types), state-field schema,
constructor-arg byte offsets, code-separator slot offsets, and OP_PUSHTX
metadata. Loaded from the JSON the compiler emits via
`RunarArtifact.fromJson(String)`.

### Contract — [`RunarContract`](src/main/java/runar/lang/sdk/RunarContract.java)

The runtime object. Wraps an `Artifact` + constructor args + state map +
the contract's currently-owned UTXO. Knows how to render its locking
script, deploy itself, call public methods, prepare unsigned calls for
external signers, and chain stateful continuations.

### Provider — [`Provider`](src/main/java/runar/lang/sdk/Provider.java)

Read/write blockchain interface. Three methods:
`listUtxos(address)`, `broadcastRaw(txHex)`, `getUtxo(txid, vout)`, plus
a `getFeeRate()` default. Implementations:
[`MockProvider`](src/main/java/runar/lang/sdk/MockProvider.java),
[`RPCProvider`](src/main/java/runar/lang/sdk/RPCProvider.java),
[`WhatsOnChainProvider`](src/main/java/runar/lang/sdk/WhatsOnChainProvider.java),
[`GorillaPoolProvider`](src/main/java/runar/lang/sdk/GorillaPoolProvider.java),
and [`WalletProvider`](src/main/java/runar/lang/sdk/WalletProvider.java).

### Signer — [`Signer`](src/main/java/runar/lang/sdk/Signer.java)

Key-management interface. `sign(sighash, derivationKey)` returns a
DER-encoded ECDSA signature; `pubKey()` returns the 33-byte compressed
secp256k1 pubkey; `address()` returns the BSV P2PKH address.
Implementations:
[`LocalSigner`](src/main/java/runar/lang/sdk/LocalSigner.java) (in-process
private key, BouncyCastle, RFC 6979 deterministic ECDSA, low-S),
[`MockSigner`](src/main/java/runar/lang/sdk/MockSigner.java) (deterministic
72-byte placeholder for tests), and
[`ExternalSigner`](src/main/java/runar/lang/sdk/ExternalSigner.java)
(marker sub-interface for hardware wallets / HSMs / multi-party flows).

### Wallet — [`BRC100Wallet`](src/main/java/runar/lang/sdk/BRC100Wallet.java)

BRC-100 wallet client. The Java type name is `BRC100Wallet` to match the
JVM convention; in TS / Go / Rust / Python the corresponding type is
called `WalletClient`. The reference test double is
[`MockBRC100Wallet`](src/main/java/runar/lang/sdk/MockBRC100Wallet.java)
which wraps one `LocalSigner` per derivation path. Wired into the SDK
via [`WalletProvider`](src/main/java/runar/lang/sdk/WalletProvider.java).

### Call — `RunarContract.call(...)` → `CallOutcome`

A method invocation on a deployed contract: spend the contract UTXO,
optionally produce a continuation UTXO with updated state, broadcast.
Stateless contracts terminate; stateful contracts roll forward.

### PreparedCall — [`PreparedCall`](src/main/java/runar/lang/sdk/PreparedCall.java)

The output of the two-pass call flow used when an external signer holds
the private key. Carries the unsigned tx hex + one BIP-143 sighash per
`Sig` placeholder + the bookkeeping that `RunarContract.finalizeCall`
needs to splice signatures back in and broadcast.

### State — `RunarContract.state()`

Mutable Bitcoin-Script-encoded payload after the contract's last
OP_RETURN. Stateful only. Encoded by
[`StateSerializer`](src/main/java/runar/lang/sdk/StateSerializer.java);
read live via `contract.state()` (whole map) or `contract.state(name)`
(single field).

### UTXO — [`UTXO`](src/main/java/runar/lang/sdk/UTXO.java)

Immutable record `(txid, outputIndex, satoshis, scriptHex)`. Tracked
across deploy → call → call.

### Inscription — [`Inscription`](src/main/java/runar/lang/sdk/Inscription.java)

Optional 1sat ordinals envelope. A `record(contentType, dataHex)` whose
`toEnvelopeHex()` produces the standard `OP_FALSE OP_IF "ord" ... OP_ENDIF`
push sequence. Spliced into the locking script between the code part and
the state section by `RunarContract.withInscription(insc)`.

---

## 6. Writing a contract

Rúnar Java contracts are regular `.runar.java` source files: `class`
definitions that `extend SmartContract` (stateless) or
`extends StatefulSmartContract` (stateful). The Rúnar Java parser
([`compilers/java/.../JavaParser.java`](../../compilers/java/src/main/java/runar/compiler/frontend/JavaParser.java))
recognises a strict subset of Java 17 syntax and produces the same AST as
the TypeScript / Go / Rust / Python / Zig / Ruby parsers.

### Annotations — [`runar.lang.annotations`](src/main/java/runar/lang/annotations)

| Annotation     | Target  | Effect                                                                    |
|----------------|---------|---------------------------------------------------------------------------|
| `@Public`      | METHOD  | Marks a method as a public spending entry point. Methods without `@Public` are private helpers (inlined by the compiler). |
| `@Readonly`    | FIELD   | Marks a `StatefulSmartContract` field as immutable. All other fields are mutable state. |
| `@Stateful`    | TYPE    | Optional — informational hint. The compiler derives statefulness from `extends StatefulSmartContract`. |

### Base classes

[`SmartContract`](src/main/java/runar/lang/SmartContract.java) — every
field is implicitly `readonly`, the developer writes the full unlocking
logic, the contract is fully spent on every call.

[`StatefulSmartContract`](src/main/java/runar/lang/StatefulSmartContract.java) —
the compiler auto-injects `checkPreimage` at the start of every public
method and a state-continuation output at the end. Mutable fields become
serialised state; `@Readonly` fields are spliced into the code part as
constructor data. The base class also exposes `protected final
SigHashPreimage txPreimage` so methods can introspect the spending
transaction.

### Constructor

The constructor must call `super(...)` as the first statement, passing
every property in declaration order. The Rúnar Java parser uses this to
infer the property → constructor-arg mapping.

### Allowed call surface

Inside a method body you may call:

- Public / private methods on `this`.
- Static methods of [`runar.lang.Builtins`](src/main/java/runar/lang/Builtins.java)
  (assertions, hashes, signature verification, EC ops, math, ByteString
  ops, post-quantum verifiers). The compiler treats every Builtin as a
  compile-time intrinsic and emits the corresponding Bitcoin Script
  opcodes.
- Methods on the `Bigint` wrapper
  ([`runar.lang.types.Bigint`](src/main/java/runar/lang/types/Bigint.java)) —
  `plus(b)`, `minus(b)`, `times(b)`, `div(b)`, `gt(b)`, `lt(b)`,
  `eq(b)`, `neg()`, `abs()`, etc. The parser lowers each call to the
  canonical arithmetic AST so the produced script is byte-identical to
  the TS equivalent.

Calling anything else — `Math.floor`, `System.out.println`, third-party
utility methods — is rejected by the typechecker. The contract surface
is the surface; nothing else compiles.

### Domain types — [`runar.lang.types`](src/main/java/runar/lang/types)

| Type                | Wraps                          | Notes                                              |
|---------------------|--------------------------------|----------------------------------------------------|
| `Bigint`            | `BigInteger`                   | The Rúnar `bigint`. Use `Bigint.ZERO`, `Bigint.of(7)`. |
| `ByteString`        | `byte[]`                       | Variable-length bytes; base type for every domain wrapper below. |
| `Sig`               | `ByteString` (~72 bytes)       | DER-encoded ECDSA signature.                       |
| `PubKey`            | `ByteString` (33 bytes)        | Compressed secp256k1 pubkey.                       |
| `Addr` / `Ripemd160`| `ByteString` (20 bytes)        | HASH160 / RIPEMD-160 digest.                       |
| `Sha256`            | `ByteString` (32 bytes)        | SHA-256 digest.                                    |
| `SigHashPreimage`   | `ByteString` (variable)        | Serialized BIP-143 sighash preimage.               |
| `Point`             | `ByteString` (64 bytes)        | secp256k1 point `(x[32] || y[32])`.                |
| `P256Point` / `P384Point` | `ByteString`             | NIST P-256 / P-384 points.                         |
| `RabinSig` / `RabinPubKey` | `BigInteger`            | Rabin-Williams signature primitives.               |
| `OpCodeType`        | enum                            | Opcode constants used by intrinsic call sites.     |
| `FixedArray<T, N>`  | typed alias                    | Compile-time fixed-length sequence.                |

### Example: a P2PKH unlock

```java
package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class P2PKH extends SmartContract {

    final Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
```

---

## 7. Compiling

[`CompileCheck`](src/main/java/runar/lang/sdk/CompileCheck.java) runs the
Rúnar Java frontend (parse → validate → expand-fixed-arrays → typecheck)
on a contract source file or string. It does not produce a binary
artifact; for that, use the `runar` CLI (see below). `CompileCheck` is
the right tool to wire into JUnit tests so a CI build catches contract
errors early.

### From a `Path`

```java
import java.nio.file.Path;
import runar.lang.sdk.CompileCheck;

CompileCheck.run(Path.of("Counter.runar.java"));
// throws CompileException if any pass reports errors;
// throws IOException if the file cannot be read.
```

Signature: `public static void run(Path file) throws IOException`.

### From a source string

```java
String source = """
    package demo;
    import runar.lang.SmartContract;
    class Empty extends SmartContract { Empty() { super(); } }
    """;
CompileCheck.check(source, "Empty.runar.java");
```

Signature: `public static void check(String source, String fileName)`.
The `fileName` extension dispatches the parser frontend (so passing
`Empty.runar.ts` would invoke the TS parser instead).

### Producing a deployable artifact

The Java compiler frontend ships in the `runar-java-compiler` Maven
artifact (composite-built from `compilers/java`). Today the Java
compiler's CLI emits ANF IR + Bitcoin Script hex but not yet the full
artifact JSON consumed by `RunarArtifact.fromJson`. To produce a
deployable artifact, run the TypeScript reference CLI — every compiler
matches it byte-for-byte:

```bash
npx tsx packages/runar-cli/src/bin.ts compile \
    examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java \
    -o build/artifacts
```

The output `build/artifacts/Counter.runar.json` can be loaded with
`RunarArtifact.fromJson(Files.readString(...))`. Once the Java compiler
emits full artifact JSON, the CLI will be a drop-in replacement.

---

## 8. Deploying contracts

Construct a `RunarContract` with an artifact and constructor args, then
call `deploy`:

```java
import java.math.BigInteger;
import java.util.List;
import runar.lang.sdk.*;

RunarArtifact artifact = RunarArtifact.fromJson(json);
RunarContract contract = new RunarContract(
    artifact,
    List.of(BigInteger.ZERO)            // constructor args, in declared order
);

Provider provider = new MockProvider("regtest");
Signer signer = new LocalSigner(privateKeyHex);

RunarContract.DeployOutcome out = contract.deploy(
    provider, signer,
    5_000L,                             // satoshis to lock in the contract output
    null                                 // change address (null = use signer's address)
);
System.out.println(out.txid());
System.out.println(out.deployedUtxo());  // tracked on the contract instance too
```

Signatures:

```java
public DeployOutcome deploy(Provider provider, Signer signer, long satoshis, String changeAddress);
public DeployOutcome deploy(Provider provider, Signer signer, long satoshis);

public record DeployOutcome(String txid, String rawTxHex, UTXO deployedUtxo) {}
```

Internally `deploy` renders the locking script via
[`ContractScript.renderLockingScript`](src/main/java/runar/lang/sdk/ContractScript.java),
selects funding UTXOs largest-first via
[`UtxoSelector`](src/main/java/runar/lang/sdk/UtxoSelector.java), estimates
the fee via
[`FeeEstimator`](src/main/java/runar/lang/sdk/FeeEstimator.java), signs
each P2PKH input with BIP-143 SIGHASH_ALL|FORKID, broadcasts via
`Provider.broadcastRaw`, and stamps the resulting UTXO on the contract.

### Reusing a deployed contract

Re-attaching to an existing on-chain contract is one explicit assignment
away — the SDK does not (yet) ship a `fromTxId` / `fromUtxo` helper:

```java
RunarContract contract = new RunarContract(artifact, ctorArgs);
contract.setCurrentUtxo(provider.getUtxo(txid, vout));
```

Once `currentUtxo()` is populated, `call(...)` and `prepareCall(...)`
behave the same as if the contract had just been deployed in-process.

### Inscriptions

```java
Inscription insc = new Inscription("text/plain", ScriptUtils.bytesToHex("hello".getBytes()));
contract.withInscription(insc);
contract.deploy(provider, signer, 5_000L);
```

The envelope is spliced between the code part and the state section, so
state continuations across `call(...)` invocations preserve it
unchanged.

---

## 9. Calling contract methods

Three flows, increasing in complexity. All three live on `RunarContract`.

### 9a. Single-signer (`call`)

The simple case. The SDK signs internally with the supplied
[`Signer`](src/main/java/runar/lang/sdk/Signer.java), splices the
signature into the unlocking script, and broadcasts.

```java
RunarContract.CallOutcome out = contract.call(
    "increment",            // method name
    List.of(),              // user-visible args (excluding auto-Sig / auto-PubKey)
    null,                   // state updates: null = compute from the call
    provider, signer
);
System.out.println(out.txid());
```

Signature:

```java
public CallOutcome call(
    String methodName,
    List<Object> args,
    Map<String, Object> stateUpdates,
    Provider provider,
    Signer signer
);
public record CallOutcome(String txid, String rawTxHex, UTXO nextContractUtxo) {}
```

Auto-computed slots inside `args`:

- A `null` entry whose ABI type is `Sig` is replaced with a 72-byte
  placeholder, and after the BIP-143 sighash is computed the SDK
  re-signs and splices the real DER signature in.
- A `null` entry whose ABI type is `PubKey` is replaced with the
  signer's `pubKey()` (hex-encoded).

`stateUpdates` lets the caller force the next state explicitly. Pass
`null` for stateless contracts; for stateful ones it's an escape hatch
for tests that want to assert that the on-chain VM rejects a forged
state (see Section 11b).

### 9b. Multi-signer (`prepareCall` / `finalizeCall`)

Use this when the private key lives outside your process: an HSM, a
hardware wallet, a multi-party signing protocol. The flow is two passes.

#### Pass 1 — prepare

```java
PreparedCall prep = contract.prepareCall(
    "increment",
    List.of(),
    null,
    provider,
    signer        // optional; provides the auto-PubKey value if any
);

// Hand each sighash to the external signer.
List<byte[]> signatures = new ArrayList<>();
for (byte[] sighash : prep.sighashes()) {
    signatures.add(externalSign(sighash));
}
```

Signature:

```java
public PreparedCall prepareCall(
    String methodName,
    List<Object> args,
    Map<String, Object> stateUpdates,
    Provider provider,
    Signer signer
);
public PreparedCall prepareCall(String methodName, List<Object> args, Provider provider, Signer signer);
public PreparedCall prepareCall(String methodName, List<Object> args, Provider provider);
```

The returned [`PreparedCall`](src/main/java/runar/lang/sdk/PreparedCall.java)
exposes only the surface an external signer needs:

- `txHex()` — the prepared (unsigned-as-to-Sig-params) tx hex, with
  72-byte zero placeholders at every `Sig` slot.
- `sighashes()` — `List<byte[]>` of 32-byte BIP-143 digests, one per
  `Sig` placeholder.
- `sigIndices()` — the user-visible arg indices each sighash maps to.
- Plus `contractUtxo()`, `methodName()`, `isStateful()` for
  introspection.

The remaining fields (`continuation`, `newLockingScriptHex`,
`newSatoshis`) are package-private bookkeeping consumed by
`finalizeCall`.

#### Pass 2 — finalize

```java
RunarContract.CallOutcome out = contract.finalizeCall(prep, signatures, provider);
System.out.println(out.txid());
```

Signature:

```java
public CallOutcome finalizeCall(
    PreparedCall prepared,
    List<byte[]> signatures,
    Provider provider
);
```

Each entry in `signatures` must be a DER-encoded ECDSA signature. The
SDK appends the standard `SIGHASH_ALL | FORKID` flag byte before the
push lands in the unlocking script. Order matters: `signatures.get(i)`
corresponds to `prepared.sigIndices().get(i)`.

The prepared tx and the finalized tx are byte-identical except for the
substituted unlocking script — BIP-143 hashes the locking script of the
input being signed, not its scriptSig, so the signatures stay valid.

### 9c. BRC-100 wallet signing (`WalletProvider`)

The Java SDK's
[`WalletProvider`](src/main/java/runar/lang/sdk/WalletProvider.java) is
**special among the seven Rúnar SDKs**: it implements both `Provider`
**and** `ExternalSigner` from a single class. The TS / Go / Rust /
Python / Ruby / Zig SDKs split the two roles into a `WalletProvider` and
a separate `WalletSigner`. The Java collapse is intentional — BRC-100
wallets typically expose both the outpoint store and the signing
capability through one client interface, so wrapping a single
[`BRC100Wallet`](src/main/java/runar/lang/sdk/BRC100Wallet.java) in one
adapter is the most direct fit.

The wallet itself never sees the unsigned transaction. The SDK computes
the BIP-143 sighash locally and only hands the wallet the 32-byte
digest — matching BRC-100's split-capability design ("I signed hash X
with key Y" without parsing locking scripts).

```java
import runar.lang.sdk.*;

BRC100Wallet wallet = new MockBRC100Wallet()
    .register("runar/app/1", LocalSigner.fromWIF("L1aW4aubDFB7yfras2S1mN3bqg9..."));

Provider rpc = new RPCProvider("http://localhost:18332/", "user", "pass");

WalletProvider wp = new WalletProvider(
    wallet,
    rpc,             // delegate Provider for UTXO lookup + broadcast
    "runar/app/1"    // default derivation path
);

// Use wp as both Provider AND Signer in a single arg.
contract.call("increment", List.of(), null, wp, wp);
```

Constructor signature:

```java
public WalletProvider(BRC100Wallet wallet, Provider delegate, String derivationPath);
```

`WalletProvider` delegates `listUtxos` / `broadcastRaw` / `getUtxo` /
`getFeeRate` to the inner provider, and routes `sign` / `pubKey` /
`address` through the wallet at the configured derivation path. Pass a
non-`null` `derivationKey` to `sign(sighash, derivationKey)` to override
the default path on a per-call basis (useful for multi-key wallets).

### Inspecting a prepared sighash

`WalletProvider.computeSighash(...)` lets you preview what a signer will
be asked to sign before triggering a hardware wallet prompt:

```java
byte[] sighash = WalletProvider.computeSighash(
    txHex, /* inputIndex */ 0, subscriptHex, inputSatoshis);
```

---

## 10. Stateful contracts

Stateful contracts hold mutable state on-chain in the locking script's
post-OP_RETURN payload. The compiler enforces three invariants on every
public method:

1. **`checkPreimage` runs first.** The compiler injects a `checkPreimage`
   call at the entry of each public method. The transaction's BIP-143
   preimage is pushed to the stack, and the contract verifies it
   matches the spending tx — anchoring the contract's view of "the new
   outputs" to the actual outputs in the transaction.
2. **A continuation output is emitted.** The compiler injects an
   `addOutput` call at the end of each non-terminal public method that
   re-encodes the contract's locking script with updated state. The
   spending tx must produce that output verbatim or `checkPreimage`
   fails.
3. **Mutable fields become state.** Fields without `@Readonly` are the
   contract's serialised state. Fields with `@Readonly` are spliced into
   the code part as constructor data and never change across spends.

OP_PUSHTX preamble injection, the `_changePKH` / `_changeAmount` /
`_newAmount` synthetic params, and the codeSeparator placement are all
SDK / compiler internals. From the contract author's perspective, you
write `this.count = this.count.plus(Bigint.ONE)` and the compiler does
the rest.

### State chaining across calls

```java
RunarContract contract = new RunarContract(artifact, List.of(BigInteger.ZERO));
contract.deploy(provider, signer, 5_000L);

contract.call("increment", List.of(), null, provider, signer);
contract.call("increment", List.of(), null, provider, signer);
contract.call("increment", List.of(), null, provider, signer);

System.out.println(contract.state("count"));   // BigInteger 3
System.out.println(contract.currentUtxo());    // tracks the latest continuation
```

`call` automatically tracks the continuation UTXO produced by each call,
so the next call spends the right output. For terminal methods (no
state continuation) the SDK clears `currentUtxo()` to `null` so a stale
reference can't accidentally be reused.

### Multi-output contracts

`this.addOutput(satoshis, value0, value1, ...)` is the multi-output
intrinsic — `values` must match the contract's mutable properties in
declaration order. `this.addRawOutput(satoshis, scriptBytes)` produces
an output with caller-specified script bytes (uncommitted by the
continuation). `this.addDataOutput(satoshis, scriptBytes)` produces an
output committed to by the continuation hash, so spenders cannot swap
it out.

Off-chain (under the simulator), all three intrinsics route into the
simulator's
[`OutputCapture`](src/main/java/runar/lang/runtime/ContractSimulator.java)
so tests can inspect what was emitted (see Section 11a).

### ANF interpreter for off-chain state computation

[`AnfInterpreter`](src/main/java/runar/lang/sdk/AnfInterpreter.java) is a
JVM-native interpreter for the compiled ANF IR. It lets you predict the
new state a stateful method will produce without broadcasting a
transaction:

```java
import runar.lang.sdk.AnfInterpreter;

Map<String, Object> anf = AnfInterpreter.loadAnf(artifactJson);
Map<String, Object> currentState = Map.of("count", BigInteger.ZERO);
Map<String, Object> args = Map.of();
List<Object> ctorArgs = List.of(BigInteger.ZERO);

Map<String, Object> newState = AnfInterpreter.computeNewState(
    anf, "increment", currentState, args, ctorArgs);
System.out.println(newState.get("count"));   // BigInteger 1
```

Two modes:

- `computeNewState(...)` — skips `assert` / `check_preimage` /
  on-chain-only ops. Returns the projected next state.
- `executeStrict(...)` — same walk, but `assert` bindings actually
  evaluate their condition and throw `AssertionFailureException` if
  false. Returns an `ExecutionResult(newState, dataOutputs)`.

Crypto primitives that aren't locally implementable
(BN254/Poseidon2/SLH-DSA/sha256Compress) bubble up
`UnsupportedOperationException` from `MockCrypto` rather than silently
returning a wrong value; test those contracts via the compiler+VM path.

---

## 11. UTXO and fee management

### Fee estimation — [`FeeEstimator`](src/main/java/runar/lang/sdk/FeeEstimator.java)

Fee math uses **actual script sizes** (not hardcoded P2PKH assumptions).
Fee rate is satoshis per 1000 bytes; the BSV default is `100`.

```java
long deployFee = FeeEstimator.estimateDeployFee(
    /* numInputs */ 2,
    /* lockingScriptByteLen */ 254,
    /* feeRate */ 100L);

long callFee = FeeEstimator.estimateCallFee(
    /* contractInputScriptLen */ 105,
    /* extraContractInputsScriptLen */ 0,
    /* p2pkhFundingInputs */ 0,
    /* contractOutputScriptLens */ new int[] { 254 },
    /* withChange */ true,
    /* feeRate */ 100L);
```

Constants you can read off the class:
`FeeEstimator.P2PKH_INPUT_SIZE` (148),
`FeeEstimator.P2PKH_OUTPUT_SIZE` (34),
`FeeEstimator.TX_OVERHEAD` (10),
`FeeEstimator.DEFAULT_FEE_RATE` (100).

### UTXO selection — [`UtxoSelector`](src/main/java/runar/lang/sdk/UtxoSelector.java)

Largest-first with fee-aware iteration:

```java
List<UTXO> selected = UtxoSelector.selectLargestFirst(
    provider.listUtxos(signer.address()),
    targetSatoshis,
    lockingScriptByteLen,
    provider.getFeeRate());
```

The selector sorts UTXOs descending by satoshi value, then accumulates
until the running total covers `target + estimatedFee(selected, ...)`.
Returns every UTXO if still short — the transaction builder produces
the definitive insufficient-funds error.

### Provider fee rate

`Provider.getFeeRate()` returns `100` by default. `MockProvider` exposes
`setFeeRate(long)` so tests can drive the selection logic. RPC providers
inherit the default; override by wrapping your provider and returning a
different rate.

---

## 12. Typed contract bindings

[`TypedContractGenerator`](src/main/java/runar/lang/sdk/codegen/TypedContractGenerator.java)
emits a typed Java wrapper class for a compiled `RunarArtifact`. The
output mirrors the wrapper classes the TS / Go / Rust / Python / Zig
SDKs generate from the same artifact — typed constructors, typed
methods, typed state accessors, with `Sig` and `SigHashPreimage` params
elided from the user-facing surface and auto-computed by the SDK.

### Generating a wrapper

```java
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.codegen.TypedContractGenerator;

RunarArtifact artifact = RunarArtifact.fromJson(json);
String src = TypedContractGenerator.generate(artifact, "runar.generated.counter");
Files.writeString(Path.of("CounterWrapper.java"), src);
```

Signature:

```java
public static String generate(RunarArtifact artifact, String packageName);
```

Throws `IllegalArgumentException` if `artifact` is `null` or
`packageName` is `null`/blank.

### What the output looks like

For the stateful `Counter` artifact (one `bigint count` field, an
`increment` non-terminal method, a `decrement` non-terminal method) the
generator emits:

```java
// Generated by: runar codegen
// Source: Counter
// Do not edit manually.

package runar.generated.counter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import runar.lang.sdk.Provider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;
import runar.lang.sdk.Signer;

public final class CounterWrapper {
    private final RunarContract inner;
    private final Provider provider;
    private final Signer signer;

    public CounterWrapper(RunarArtifact artifact, BigInteger count, Provider provider, Signer signer) {
        List<Object> args = new ArrayList<>();
        args.add(count);
        this.inner = new RunarContract(artifact, args);
        this.provider = provider;
        this.signer = signer;
    }

    public RunarContract contract() { return inner; }

    public String deploy(BigInteger satoshis) {
        return inner.deploy(provider, signer, satoshis.longValueExact()).txid();
    }

    public String increment() {
        List<Object> callArgs = new ArrayList<>();
        return inner.call("increment", callArgs, null, provider, signer).txid();
    }

    public String decrement() {
        List<Object> callArgs = new ArrayList<>();
        return inner.call("decrement", callArgs, null, provider, signer).txid();
    }

    public BigInteger count() {
        return (BigInteger) inner.state("count");
    }
}
```

### Type mapping

| ABI type                                            | Generated Java type |
|-----------------------------------------------------|---------------------|
| `bigint`, `int`                                     | `BigInteger`        |
| `boolean`, `bool`                                   | `boolean`           |
| `Sig`                                                | `Sig` (elided from public methods) |
| `PubKey`                                             | `PubKey`            |
| `Addr`                                               | `Addr`              |
| `ByteString`, `Ripemd160`, `Sha256`, `Point`, `SigHashPreimage` | `ByteString` |
| anything else                                       | `Object` (fallback) |

### Method classification

- **Terminal methods** (stateless, or stateful methods marked
  `isTerminal: true`, or stateful methods missing the `_changePKH`
  synthetic param) generate `void` returns.
- **Non-terminal stateful methods** generate `String` returns (the
  broadcast txid).
- **`Sig` params** are elided from the user-facing signature; the SDK
  signs internally and substitutes via the placeholder mechanism.
- **`SigHashPreimage` params** on stateful methods are elided as
  internal — the compiler binds them to `this.txPreimage`.
- **`_changePKH`, `_changeAmount`, `_newAmount` synthetic params** on
  stateful methods are elided.

### Method-name collisions

Method names that would collide with the wrapper's own surface
(`contract`, `deploy`, `provider`, `signer`, `inner`, `state`) are
emitted as `callContract`, `callDeploy`, ... — matching the TS / Go
`safeMethodName` helper.

### State accessors

For each stateful state field, the generator emits a typed accessor:

```java
public BigInteger count() {
    return (BigInteger) inner.state("count");
}
```

The cast is generated using the same ABI-type table as method params.

### Compiling the generated source

The generated class only depends on `runar-java` types — no extra
dependencies. Drop the file into `src/main/java/...` and your normal
Gradle build picks it up.

---

## 13. Testing

### 13a. Off-chain testing

Two tools, two layers:

#### `ContractSimulator` — native JVM execution with mocked crypto

[`ContractSimulator`](src/main/java/runar/lang/runtime/ContractSimulator.java)
runs `SmartContract` / `StatefulSmartContract` instances natively on the
JVM. It activates the
[`SimulatorContext`](src/main/java/runar/lang/runtime/SimulatorContext.java)
thread-local for the duration of each `call(...)` so the static methods
in `runar.lang.Builtins` route into real implementations
([`MockCrypto`](src/main/java/runar/lang/runtime/MockCrypto.java)) instead
of throwing. Hashes (SHA-256 / RIPEMD-160 / hash160 / hash256), EC ops
(secp256k1 via BouncyCastle), Blake3, post-quantum verifiers (WOTS,
SLH-DSA SHA-2 family), NIST P-256/P-384 ECDSA, and partial SHA-256
(`sha256Compress` / `sha256Finalize`) are real. Signature verification
is mocked to always succeed (real ECDSA needs a full transaction
context, which is the Script VM's job).

```java
import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CounterTest {

    @Test
    void simulatorIncrementsCount() {
        Counter c = new Counter(Bigint.of(7));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment");
        assertEquals(Bigint.of(8), c.count);
    }

    @Test
    void simulatorRejectsDecrementBelowZero() {
        Counter c = new Counter(Bigint.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c);
        assertThrows(AssertionError.class, () -> sim.call("decrement"));
    }
}
```

API surface:

```java
public static ContractSimulator stateless(SmartContract contract);
public static ContractSimulator stateful(StatefulSmartContract contract);

public Object call(String methodName, Object... args);
public Object callStateful(String methodName, Preimage preimage, Object... args);
public AssertionError expectFailure(String methodName, Object... args);

public List<Output> outputs();    // captured this.addOutput / addRawOutput / addDataOutput emissions
public Preimage lastPreimage();
public SmartContract contract();
```

Output capture is a thread-local stack, so nested simulator instances
work in concurrent tests. Each captured `Output` exposes
`kind` (STATE / RAW / DATA), `satoshis`, `values` (positional, matching
mutable property declaration order), and `rawScriptBytes` (non-null for
RAW / DATA outputs).

For methods that need a structured BIP-143 preimage, build one via
[`Preimage.builder()`](src/main/java/runar/lang/runtime/Preimage.java):

```java
Preimage preimage = Preimage.builder()
    .version(2L)
    .amount(BigInteger.valueOf(5000))
    .locktime(0L)
    .build();
sim.callStateful("methodThatReadsPreimage", preimage, arg0, arg1);
```

#### `AnfInterpreter` — ANF-IR-based execution

[`AnfInterpreter`](src/main/java/runar/lang/sdk/AnfInterpreter.java)
runs the compiled ANF IR rather than the Java source — useful when you
want to verify what the compiler produced, or when the contract source
isn't checked in alongside the artifact.

```java
import runar.lang.sdk.AnfInterpreter;

Map<String, Object> anf = AnfInterpreter.loadAnf(artifactJson);

AnfInterpreter.ExecutionResult result = AnfInterpreter.executeStrict(
    anf, "increment",
    Map.of("count", BigInteger.ZERO),
    Map.of(),
    List.of(BigInteger.ZERO));

assertEquals(BigInteger.ONE, result.newState.get("count"));
assertTrue(result.dataOutputs.isEmpty());
```

In strict mode an `assert` binding throws
`AnfInterpreter.AssertionFailureException`; in `computeNewState` mode it
silently no-ops. Either mode skips on-chain-only ops
(`check_preimage`, `deserialize_state`, `get_state_script`,
`add_raw_output`).

#### `CompileCheck` in tests

Pair business-logic tests with a frontend smoke test so source-level
breakage is caught immediately:

```java
@Test
void contractCompiles() throws Exception {
    CompileCheck.run(Path.of("Counter.runar.java"));
}
```

### 13b. Integration testing against a regtest node

The reference setup lives in
[`integration/java/`](../../integration/java) — a separate Gradle build
that depends on `runar-java`, gates every test behind
`-Drunar.integration=true`, and exercises the full deploy → call →
broadcast loop against a real BSV regtest node.

```bash
cd integration && ./regtest.sh start          # start an SV Node regtest
cd java && gradle test -Drunar.integration=true
```

The Counter integration test
([`integration/java/.../CounterIntegrationTest.java`](../../integration/java/src/test/java/runar/integration/CounterIntegrationTest.java))
covers the canonical flows:

```java
import org.junit.jupiter.api.Test;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;
import runar.integration.helpers.*;

import static org.junit.jupiter.api.Assertions.*;

class CounterIntegrationTest extends IntegrationBase {

    @Test
    void incrementOnce() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/stateful-counter/Counter.runar.ts");

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.ZERO));
        contract.deploy(provider, wallet.signer(), 5_000L);
        RunarContract.CallOutcome out = contract.call(
            "increment", List.of(), null, provider, wallet.signer());
        assertNotNull(out.txid());
    }

    @Test
    void rejectWrongState() {
        // Forge a state map and prove the on-chain VM rejects it.
        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.ZERO));
        contract.deploy(provider, wallet.signer(), 5_000L);

        Map<String, Object> badState = Map.of("count", BigInteger.valueOf(99));
        assertThrows(RuntimeException.class, () ->
            contract.call("increment", List.of(), badState, provider, wallet.signer()));
    }
}
```

The `IntegrationBase` superclass is gated by
`@EnabledIfSystemProperty(named = "runar.integration", matches = "true")`,
so plain `gradle test` in CI without a node is a no-op. The test also
refuses to run on mainnet or testnet — regtest is the only allowed
network.

### Cross-SDK output conformance

`conformance/sdk-output/tests/stateful-counter/{input.json,
expected-locking.hex}` validates that all seven SDKs produce
byte-identical deployed locking scripts for the Counter artifact +
constructor args. The Java SDK is in that suite — proof of cross-SDK
parity, not just functional equivalence.

---

## 14. Provider configuration

Six in-tree providers; pick by deployment target.

### `MockProvider` — in-memory tests

```java
MockProvider provider = new MockProvider("regtest");
provider.addUtxo(address, new UTXO(txid, vout, satoshis, scriptHex));
provider.setFeeRate(50L);
List<String> broadcasts = provider.getBroadcastedTxs();   // assertions
```

Broadcasts return a deterministic mock txid (FNV-style hash of the
broadcast count + txhex prefix) so tests can pin exact txid strings.

### `RPCProvider` — Bitcoin-Core / SV-Node JSON-RPC

```java
RPCProvider provider = new RPCProvider(
    "http://localhost:18332/", "user", "pass");

// Regtest convenience: auto-mines one block after every broadcast.
RPCProvider regtest = RPCProvider.regtest(
    "http://localhost:18332/", "user", "pass");

String hex = provider.getRawTransaction(txid);
```

Methods used: `listunspent`, `sendrawtransaction`, `getrawtransaction`
(verbose), `generate` / `generatetoaddress` (regtest auto-mine).
Authentication is HTTP Basic over the `Authorization` header. Failures
raise [`ProviderException`](src/main/java/runar/lang/sdk/ProviderException.java)
with the upstream JSON-RPC error message preserved when available.

### `WhatsOnChainProvider` — REST against WoC

```java
WhatsOnChainProvider provider = new WhatsOnChainProvider("mainnet");   // or "testnet"
String hex = provider.getRawTransaction(txid);
```

Endpoints used: `/address/{addr}/unspent`, `/tx/raw`,
`/tx/hash/{txid}`, `/tx/{txid}/hex`. The unspent listing does not
include the locking script — fetch via `getUtxo(...)` when needed.

### `GorillaPoolProvider` — REST against GorillaPool / 1sat ordinals

```java
GorillaPoolProvider provider = new GorillaPoolProvider("mainnet");
String balance = provider.getBSV20Balance(address, "RUNAR");
List<UTXO> utxos = provider.getBSV21Utxos(address, "<txid>_<vout>");
List<UTXO> contractUtxos = provider.getContractUtxos(scriptHash);
```

In addition to the `Provider` surface, GorillaPool exposes BSV-20 /
BSV-21 token-balance + token-UTXO helpers and a script-hash UTXO lookup
useful for stateful-contract continuations.

### `WalletProvider` — BRC-100 wallet

See Section 7c.

### Custom providers

Implement [`Provider`](src/main/java/runar/lang/sdk/Provider.java):

```java
public interface Provider {
    List<UTXO> listUtxos(String address);
    String broadcastRaw(String txHex);
    UTXO getUtxo(String txid, int vout);
    default long getFeeRate() { return 100L; }
}
```

For HTTP-backed implementations, the package-private
`HttpTransport` seam can be wrapped to mock responses in unit tests
(see `RPCProviderTest`, `WhatsOnChainProviderTest`,
`GorillaPoolProviderTest` for the pattern).

---

## 15. Full API reference

Alphabetical by class. Every public type, method, field, and constant
that ships in `runar-java`. Constructors and accessors for `record`
types are listed once.

### `runar.lang.Builtins`

Static facade for every Rúnar built-in function. The compiler treats each
method as a compile-time intrinsic; outside of the simulator (see
[`SimulatorContext`](src/main/java/runar/lang/runtime/SimulatorContext.java)),
calling one throws `UnsupportedOperationException`.

```java
public static void assertThat(boolean condition);

// Hashing
public static Addr hash160(PubKey pubKey);
public static Addr hash160(ByteString data);
public static ByteString sha256(ByteString data);
public static ByteString ripemd160(ByteString data);
public static ByteString hash256(ByteString data);
public static ByteString sha256Compress(ByteString state, ByteString block);
public static ByteString sha256Finalize(ByteString state, ByteString remaining, BigInteger msgBitLen);
public static ByteString blake3Hash(ByteString data);
public static ByteString blake3Compress(ByteString state, ByteString block);

// Signatures
public static boolean checkSig(Sig sig, PubKey pubKey);
public static boolean checkMultiSig(Sig[] sigs, PubKey[] pubKeys);
public static boolean verifyRabinSig(ByteString msg, BigInteger sig, ByteString padding, BigInteger pubKey);
public static boolean verifyRabinSig(ByteString msg, RabinSig sig, ByteString padding, RabinPubKey pubKey);
public static boolean verifyWOTS(ByteString msg, ByteString sig, ByteString pubKey);
public static boolean verifySLHDSA_SHA2_128s(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifySLHDSA_SHA2_128f(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifySLHDSA_SHA2_192s(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifySLHDSA_SHA2_192f(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifySLHDSA_SHA2_256s(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifySLHDSA_SHA2_256f(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifyECDSA_P256(ByteString msg, ByteString sig, ByteString pk);
public static boolean verifyECDSA_P384(ByteString msg, ByteString sig, ByteString pk);

// Math
public static BigInteger abs(BigInteger x);
public static BigInteger min(BigInteger a, BigInteger b);
public static BigInteger max(BigInteger a, BigInteger b);
public static boolean within(BigInteger v, BigInteger lo, BigInteger hi);
public static BigInteger safediv(BigInteger a, BigInteger b);
public static BigInteger safemod(BigInteger a, BigInteger b);
public static BigInteger clamp(BigInteger v, BigInteger lo, BigInteger hi);
public static BigInteger sign(BigInteger x);
public static BigInteger pow(BigInteger b, BigInteger e);
public static BigInteger mulDiv(BigInteger a, BigInteger b, BigInteger c);
public static BigInteger percentOf(BigInteger a, BigInteger bps);
public static BigInteger sqrt(BigInteger n);
public static BigInteger gcd(BigInteger a, BigInteger b);
public static BigInteger log2(BigInteger n);
public static boolean bool(BigInteger v);

// ByteString operations
public static BigInteger len(ByteString bs);
public static ByteString cat(ByteString a, ByteString b);
public static ByteString substr(ByteString bs, BigInteger start, BigInteger len);
public static ByteString left(ByteString bs, BigInteger len);
public static ByteString right(ByteString bs, BigInteger len);
public static ByteString[] split(ByteString bs, BigInteger idx);
public static ByteString reverseBytes(ByteString bs);
public static ByteString num2bin(BigInteger v, BigInteger len);
public static BigInteger bin2num(ByteString bs);
public static ByteString int2str(BigInteger v, BigInteger len);

// secp256k1 EC
public static MockCrypto.Point ecAdd(MockCrypto.Point a, MockCrypto.Point b);
public static MockCrypto.Point ecMul(MockCrypto.Point p, BigInteger k);
public static MockCrypto.Point ecMulGen(BigInteger k);
public static MockCrypto.Point ecNegate(MockCrypto.Point p);
public static boolean ecOnCurve(MockCrypto.Point p);
public static BigInteger ecModReduce(BigInteger v, BigInteger m);
public static ByteString ecEncodeCompressed(MockCrypto.Point p);
public static MockCrypto.Point ecMakePoint(BigInteger x, BigInteger y);
public static BigInteger ecPointX(MockCrypto.Point p);
public static BigInteger ecPointY(MockCrypto.Point p);

// NIST P-256 / P-384 EC (compile-time intrinsics; no off-chain mock)
public static P256Point p256Add(P256Point a, P256Point b);
public static P256Point p256Mul(P256Point p, BigInteger k);
public static P256Point p256MulGen(BigInteger k);
public static P256Point p256Negate(P256Point p);
public static boolean p256OnCurve(P256Point p);
public static ByteString p256EncodeCompressed(P256Point p);
public static P384Point p384Add(P384Point a, P384Point b);
public static P384Point p384Mul(P384Point p, BigInteger k);
public static P384Point p384MulGen(BigInteger k);
public static P384Point p384Negate(P384Point p);
public static boolean p384OnCurve(P384Point p);
public static ByteString p384EncodeCompressed(P384Point p);

// Preimage
public static boolean checkPreimage(Preimage preimage);
public static boolean checkPreimage(SigHashPreimage preimage);
public static BigInteger extractVersion(SigHashPreimage p);
public static BigInteger extractVersion(Preimage p);
public static ByteString extractHashPrevouts(SigHashPreimage p);
public static ByteString extractHashPrevouts(Preimage p);
public static ByteString extractOutpoint(SigHashPreimage p);
public static ByteString extractOutpoint(Preimage p);
public static BigInteger extractLocktime(SigHashPreimage p);
public static BigInteger extractLocktime(Preimage p);
public static ByteString extractOutputHash(SigHashPreimage p);
public static ByteString extractOutputHash(Preimage p);
public static BigInteger extractAmount(SigHashPreimage p);
public static BigInteger extractAmount(Preimage p);
public static BigInteger extractSigHashType(SigHashPreimage p);
public static BigInteger extractSigHashType(Preimage p);

// Baby Bear field arithmetic (Bigint-typed shims for source compatibility)
public static Bigint bbFieldAdd(Bigint a, Bigint b);
public static Bigint bbFieldSub(Bigint a, Bigint b);
public static Bigint bbFieldMul(Bigint a, Bigint b);
public static Bigint bbFieldInv(Bigint a);

// Baby Bear Ext4 (typecheck-only — runtime throws)
public static Bigint bbExt4Mul0(Bigint a0, Bigint a1, Bigint a2, Bigint a3,
                                Bigint b0, Bigint b1, Bigint b2, Bigint b3);
// ... bbExt4Mul1, bbExt4Mul2, bbExt4Mul3, bbExt4Inv0, bbExt4Inv1, bbExt4Inv2, bbExt4Inv3

// Merkle proof
public static ByteString merkleRootSha256(ByteString leaf, ByteString proof, Bigint index, Bigint depth);
public static ByteString merkleRootHash256(ByteString leaf, ByteString proof, Bigint index, Bigint depth);
```

### `runar.lang.SmartContract`

Base class for stateless contracts.

```java
protected SmartContract(Object... constructorArgs);
protected final void addOutput(BigInteger satoshis, Object... values);
protected final void addOutput(Bigint satoshis, Object... values);
protected final void addOutput(long satoshis, Object... values);
protected final void addRawOutput(BigInteger satoshis, byte[] scriptBytes);
protected final void addRawOutput(long satoshis, byte[] scriptBytes);
protected final void addRawOutput(BigInteger satoshis, ByteString scriptBytes);
protected final void addRawOutput(long satoshis, ByteString scriptBytes);
protected final void addDataOutput(BigInteger satoshis, ByteString scriptBytes);
protected final void addDataOutput(long satoshis, ByteString scriptBytes);
```

The `addOutput` / `addRawOutput` / `addDataOutput` methods throw
`UnsupportedOperationException` outside the simulator (the real emission
happens on-chain).

### `runar.lang.StatefulSmartContract`

Base class for stateful contracts. Extends `SmartContract`.

```java
protected final SigHashPreimage txPreimage;

protected StatefulSmartContract(Object... constructorArgs);
protected final Preimage currentPreimage();
```

`currentPreimage()` returns the active simulator's preimage when inside
`callStateful`, or `null` outside the simulator.

### `runar.lang.annotations.Public`

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Public {}
```

### `runar.lang.annotations.Readonly`

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Readonly {}
```

### `runar.lang.annotations.Stateful`

```java
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Stateful {}
```

### `runar.lang.runtime.ContractSimulator`

Off-chain harness for `SmartContract` / `StatefulSmartContract`.

```java
public static ContractSimulator stateless(SmartContract contract);
public static ContractSimulator stateful(StatefulSmartContract contract);

public Object call(String methodName, Object... args);
public Object callStateful(String methodName, Preimage preimage, Object... args);
public AssertionError expectFailure(String methodName, Object... args);

public SmartContract contract();
public List<Output> outputs();
public Preimage lastPreimage();

// Static delegation hooks (called by SmartContract; not user-facing).
public static void captureOutput(BigInteger satoshis, Object[] values);
public static void captureRawOutput(BigInteger satoshis, byte[] script);
public static void captureDataOutput(BigInteger satoshis, byte[] script);

// Output record
public static final class Output {
    public enum Kind { STATE, RAW, DATA }
    public final Kind kind;
    public final BigInteger satoshis;
    public final Object[] values;
    public final byte[] rawScriptBytes;
    public boolean isRaw();
    public boolean isData();
    public boolean isState();
}
```

### `runar.lang.runtime.MockCrypto`

Simulator implementations of every crypto / math / ByteString builtin.
Public so test harnesses can call them directly when they need real
hashes outside the simulator.

```java
public static byte[] sha256(byte[] data);
public static byte[] hash256(byte[] data);
public static byte[] ripemd160(byte[] data);
public static byte[] hash160(byte[] data);
public static Addr hash160(PubKey pubKey);
public static Addr hash160(ByteString bs);
public static ByteString sha256(ByteString data);
// ... mirrors the Builtins surface; see source for the full set.

public static final class Point { /* secp256k1 affine point */ }
```

### `runar.lang.runtime.Preimage`

Structured BIP-143 preimage builder.

```java
public static Preimage zero();
public static Builder builder();
public static Preimage parse(byte[] bytes);

public long version();
public byte[] hashPrevouts();
public byte[] hashSequence();
public byte[] outpoint();
public ByteString scriptCode();
public BigInteger amount();
public long sequence();
public byte[] hashOutputs();
public long locktime();
public long sighashType();

public byte[] toBytes();
public ByteString toByteString();

public static final class Builder {
    public Builder version(long v);
    public Builder hashPrevouts(byte[] b);
    public Builder hashSequence(byte[] b);
    public Builder outpoint(byte[] b);
    public Builder scriptCode(ByteString s);
    public Builder amount(BigInteger v);
    public Builder sequence(long s);
    public Builder hashOutputs(byte[] b);
    public Builder locktime(long l);
    public Builder sighashType(long t);
    public Preimage build();
}

// Static accessors used by Builtins.extract*
public static BigInteger extractVersion(Preimage p);
public static ByteString extractHashPrevouts(Preimage p);
public static ByteString extractOutpoint(Preimage p);
public static BigInteger extractLocktime(Preimage p);
public static ByteString extractOutputHash(Preimage p);
public static BigInteger extractAmount(Preimage p);
public static BigInteger extractSigHashType(Preimage p);
public static boolean checkPreimage(Preimage p);
```

### `runar.lang.runtime.SimulatorContext`

Thread-local switch that gates the `Builtins` mock dispatch.

```java
public static boolean isActive();
public static void enter();
public static void exit();
public static void setCurrentPreimage(Preimage p);
public static void clearCurrentPreimage();
public static Preimage currentPreimage();
```

### `runar.lang.types.Bigint`

```java
public static final Bigint ZERO;
public static final Bigint ONE;
public static final Bigint TWO;
public static final Bigint TEN;

public Bigint(BigInteger value);
public Bigint(long value);
public static Bigint of(long v);
public static Bigint of(BigInteger v);

public BigInteger value();

// Arithmetic (lowered to AST during compile)
public Bigint plus(Bigint other);
public Bigint minus(Bigint other);
public Bigint times(Bigint other);
public Bigint div(Bigint other);
public Bigint mod(Bigint other);
public Bigint shl(Bigint other);
public Bigint shr(Bigint other);
public Bigint and(Bigint other);
public Bigint or(Bigint other);
public Bigint xor(Bigint other);

// Comparisons
public boolean gt(Bigint other);
public boolean lt(Bigint other);
public boolean ge(Bigint other);
public boolean le(Bigint other);
public boolean eq(Bigint other);
public boolean neq(Bigint other);

// Unary
public Bigint neg();
public Bigint abs();
```

Implements `equals` / `hashCode` over the wrapped `BigInteger`.

### `runar.lang.types.ByteString`

Variable-length byte container; base class for `Sig`, `PubKey`, `Addr`,
`Sha256`, `Ripemd160`, `Point`, `SigHashPreimage`, `P256Point`,
`P384Point`.

```java
public ByteString(byte[] bytes);
public static ByteString fromHex(String hex);

public byte[] toByteArray();
public int length();
public String toHex();
```

Subclasses each add a `fromHex(String)` static factory and inherit
`toByteArray()` / `length()` / `toHex()` / `equals` / `hashCode`.

### `runar.lang.types.{Addr, FixedArray, OpCodeType, P256Point, P384Point, Point, PubKey, RabinPubKey, RabinSig, Ripemd160, Sha256, Sha256Digest, Sig, SigHashPreimage}`

Branded `ByteString` (or `BigInteger`) sub-types. Each has:

```java
public X(byte[] bytes);
public static X fromHex(String hex);
```

`SigHashPreimage` additionally exposes `byte[] bytes()` as a synonym
for `toByteArray()`.

### `runar.lang.sdk.AnfInterpreter`

ANF IR interpreter for off-chain stateful execution.

```java
public static Map<String, Object> computeNewState(
    Map<String, Object> anf,
    String methodName,
    Map<String, Object> currentState,
    Map<String, Object> args,
    List<Object> constructorArgs);

public static ExecutionResult executeStrict(
    Map<String, Object> anf,
    String methodName,
    Map<String, Object> currentState,
    Map<String, Object> args,
    List<Object> constructorArgs);

public static Map<String, Object> loadAnf(String json);

public static final class ExecutionResult {
    public final Map<String, Object> newState;
    public final List<DataOutput> dataOutputs;
}

public record DataOutput(long satoshis, String script) {}

public static final class AssertionFailureException extends RuntimeException {}
public static final class InterpreterException extends RuntimeException {}
```

### `runar.lang.sdk.BRC100Wallet`

```java
public interface BRC100Wallet {
    byte[] sign(byte[] sighash, String derivationPath);
    byte[] pubKey(String derivationPath);
    String address(String derivationPath);
}
```

Implementations must be thread-safe and deterministic for a given path.

### `runar.lang.sdk.CompileCheck`

```java
public static void check(String source, String fileName);
public static void run(Path file) throws IOException;
```

`check` and `run` both throw `CompileException` if any frontend pass
reports errors.

### `runar.lang.sdk.CompileException`

```java
public final class CompileException extends RuntimeException {
    public CompileException(String message, List<String> errors);
    public CompileException(String message, List<String> errors, Throwable cause);
    public List<String> errors();
}
```

### `runar.lang.sdk.ExternalSigner`

Marker sub-interface of `Signer`.

```java
public interface ExternalSigner extends Signer {}
```

### `runar.lang.sdk.FeeEstimator`

```java
public static final int P2PKH_INPUT_SIZE  = 148;
public static final int P2PKH_OUTPUT_SIZE = 34;
public static final int TX_OVERHEAD       = 10;
public static final long DEFAULT_FEE_RATE = 100L;

public static long estimateDeployFee(int numInputs, int lockingScriptByteLen, long feeRate);
public static int  varIntByteSize(long n);
public static long estimateCallFee(
    int contractInputScriptLen,
    int extraContractInputsScriptLen,
    int p2pkhFundingInputs,
    int[] contractOutputScriptLens,
    boolean withChange,
    long feeRate);
```

### `runar.lang.sdk.GorillaPoolProvider`

```java
public GorillaPoolProvider();                           // mainnet, default transport
public GorillaPoolProvider(String network);             // "mainnet" | "testnet"

public String getNetwork();
public String getBaseUrl();

// Provider
public List<UTXO> listUtxos(String address);
public String broadcastRaw(String txHex);
public UTXO getUtxo(String txid, int vout);

// Provider extensions
public String getRawTransaction(String txid);
public List<UTXO> getContractUtxos(String scriptHash);

// Token helpers
public String getBSV20Balance(String address, String tick);
public List<UTXO> getBSV20Utxos(String address, String tick);
public String getBSV21Balance(String address, String id);
public List<UTXO> getBSV21Utxos(String address, String id);
```

### `runar.lang.sdk.Inscription`

```java
public record Inscription(String contentType, String data) {
    public String toEnvelopeHex();
    public static String buildEnvelope(String contentType, String dataHex);
}
```

### `runar.lang.sdk.LocalSigner`

```java
public LocalSigner(String privKeyHex);                    // 64-char hex
public static LocalSigner fromWIF(String wif);            // throws IllegalArgumentException
public static LocalSigner random(SecureRandom rng);

// Signer
public byte[] sign(byte[] sighash, String derivationKey); // ignores derivationKey
public byte[] pubKey();
public String address();                                  // mainnet P2PKH Base58Check
```

Signatures are RFC 6979 deterministic ECDSA (HMAC-SHA-256) with
low-S normalisation per BIP-62 / BSV consensus.

### `runar.lang.sdk.MockBRC100Wallet`

```java
public MockBRC100Wallet register(String derivationPath, LocalSigner signer);
public MockBRC100Wallet registerRandom(String derivationPath);
public Map<String, LocalSigner> signers();
public int signCount(String derivationPath);

// BRC100Wallet
public byte[] sign(byte[] sighash, String derivationPath);
public byte[] pubKey(String derivationPath);
public String address(String derivationPath);
```

### `runar.lang.sdk.MockProvider`

```java
public MockProvider();                                    // network = "testnet"
public MockProvider(String network);

public String getNetwork();
public void addUtxo(String address, UTXO utxo);
public List<String> getBroadcastedTxs();
public void setFeeRate(long rate);

// Provider
public List<UTXO> listUtxos(String address);
public String broadcastRaw(String txHex);
public UTXO getUtxo(String txid, int vout);
public long getFeeRate();
```

### `runar.lang.sdk.MockSigner`

```java
public static final byte[] DEFAULT_PUBKEY;       // 0x02 || 32 zero bytes
public static final String DEFAULT_ADDRESS;      // "0".repeat(40)
public static final byte[] DEFAULT_SIGNATURE;    // 72-byte 0x30 || 70 zero || 0x41

public MockSigner();
public MockSigner(byte[] pubKey, String address);

public byte[] sign(byte[] sighash, String derivationKey);
public byte[] pubKey();
public String address();
```

### `runar.lang.sdk.PreparedCall`

```java
public final class PreparedCall {
    public String txHex();
    public List<byte[]> sighashes();
    public List<Integer> sigIndices();
    public UTXO contractUtxo();
    public String methodName();
    public boolean isStateful();
}
```

Constructed exclusively by `RunarContract.prepareCall`. Immutable, safe
to serialise across processes.

### `runar.lang.sdk.Provider`

```java
public interface Provider {
    List<UTXO> listUtxos(String address);
    String broadcastRaw(String txHex);
    UTXO getUtxo(String txid, int vout);
    default long getFeeRate() { return 100L; }
}
```

### `runar.lang.sdk.ProviderException`

```java
public class ProviderException extends RuntimeException {
    public ProviderException(String message);
    public ProviderException(String message, Throwable cause);
    public ProviderException(String message, int statusCode);
    public ProviderException(String message, int statusCode, Throwable cause);
    public int statusCode();
}
```

### `runar.lang.sdk.RPCProvider`

```java
public RPCProvider(String url, String user, String pass);
public static RPCProvider regtest(String url, String user, String pass);

public String getNetwork();
public boolean isAutoMine();

// Provider
public List<UTXO> listUtxos(String address);
public String broadcastRaw(String txHex);
public UTXO getUtxo(String txid, int vout);

// Extensions
public String getRawTransaction(String txid);
```

### `runar.lang.sdk.RunarArtifact`

```java
public record RunarArtifact(
    String version,
    String compilerVersion,
    String contractName,
    ABI abi,
    String scriptHex,
    String asm,
    String buildTimestamp,
    List<StateField> stateFields,
    List<ConstructorSlot> constructorSlots,
    List<CodeSepIndexSlot> codeSepIndexSlots,
    Integer codeSeparatorIndex,
    List<Integer> codeSeparatorIndices
) {
    public boolean isStateful();
    public static RunarArtifact fromJson(String json);
}

public record ABI(ABIConstructor constructor, List<ABIMethod> methods) {}
public record ABIConstructor(List<ABIParam> params) {}
public record ABIMethod(String name, List<ABIParam> params, boolean isPublic, Boolean isTerminal) {}
public record ABIParam(String name, String type, FixedArrayMeta fixedArray) {}
public record FixedArrayMeta(String elementType, int length, List<String> syntheticNames) {}
public record StateField(String name, String type, int index, Object initialValue, FixedArrayMeta fixedArray) {}
public record ConstructorSlot(int paramIndex, int byteOffset) {}
public record CodeSepIndexSlot(int byteOffset, int codeSepIndex) {}
```

### `runar.lang.sdk.RunarContract`

```java
public RunarContract(RunarArtifact artifact, List<Object> constructorArgs);

public RunarArtifact artifact();
public Map<String, Object> state();
public Object state(String fieldName);
public UTXO currentUtxo();
public void setCurrentUtxo(UTXO utxo);
public String lockingScript();
public RunarContract withInscription(Inscription insc);
public Inscription inscription();

public DeployOutcome deploy(Provider provider, Signer signer, long satoshis);
public DeployOutcome deploy(Provider provider, Signer signer, long satoshis, String changeAddress);

public CallOutcome call(
    String methodName,
    List<Object> args,
    Map<String, Object> stateUpdates,
    Provider provider,
    Signer signer);

public PreparedCall prepareCall(
    String methodName, List<Object> args, Provider provider);
public PreparedCall prepareCall(
    String methodName, List<Object> args, Provider provider, Signer signer);
public PreparedCall prepareCall(
    String methodName, List<Object> args, Map<String, Object> stateUpdates,
    Provider provider, Signer signer);

public CallOutcome finalizeCall(
    PreparedCall prepared, List<byte[]> signatures, Provider provider);

public record DeployOutcome(String txid, String rawTxHex, UTXO deployedUtxo) {}
public record CallOutcome(String txid, String rawTxHex, UTXO nextContractUtxo) {}
```

Constructor throws `IllegalArgumentException` if `constructorArgs.size()`
does not match the artifact's declared constructor arity. `call` /
`prepareCall` throw `IllegalStateException` if invoked before deploy.
`finalizeCall` throws `IllegalArgumentException` if signature count or
DER shape is wrong.

### `runar.lang.sdk.Signer`

```java
public interface Signer {
    byte[] sign(byte[] sighash, String derivationKey);
    byte[] pubKey();
    String address();
}
```

### `runar.lang.sdk.StateSerializer`

```java
public static String serialize(List<StateField> fields, Map<String, Object> values);
public static Map<String, Object> deserialize(List<StateField> fields, String scriptHex);
public static Map<String, Object> extractFromScript(RunarArtifact artifact, String scriptHex);
```

`extractFromScript` returns `null` for stateless contracts.

### `runar.lang.sdk.TransactionBuilder`

```java
public static DeployResult buildDeployTransaction(
    RunarArtifact artifact, List<Object> constructorArgs,
    Provider provider, Signer signer, long satoshis, String changeAddress);

public static DeployResult buildDeployWithLockingScript(
    String lockingScriptHex, Provider provider, Signer signer,
    long satoshis, String changeAddress);

public static CallResult buildCallTransaction(
    RunarArtifact artifact, UTXO contractUtxo,
    String unlockingScriptHex, Map<String, Object> stateUpdates,
    long newContractSatoshis, Provider provider, Signer signer,
    String changeAddress);

public record DeployResult(String txHex, String lockingScriptHex, List<UTXO> spentInputs) {}
public record CallResult(String txHex, String newLockingScriptHex) {}
```

### `runar.lang.sdk.UTXO`

```java
public record UTXO(String txid, int outputIndex, long satoshis, String scriptHex) {}
```

Compact constructor enforces non-null `txid` / `scriptHex` and
non-negative `outputIndex` / `satoshis`.

### `runar.lang.sdk.UtxoSelector`

```java
public static List<UTXO> selectLargestFirst(
    List<UTXO> utxos,
    long targetSatoshis,
    int lockingScriptByteLen,
    long feeRate);
```

### `runar.lang.sdk.WalletProvider`

```java
public WalletProvider(BRC100Wallet wallet, Provider delegate, String derivationPath);

public String derivationPath();
public BRC100Wallet wallet();

// Provider
public List<UTXO> listUtxos(String address);
public String broadcastRaw(String txHex);
public UTXO getUtxo(String txid, int vout);
public long getFeeRate();

// ExternalSigner
public byte[] sign(byte[] sighash, String derivationKey);
public byte[] pubKey();
public byte[] pubKey(String derivationPath);
public String address();
public String address(String derivationPath);

public static byte[] computeSighash(
    String txHex, int inputIndex, String subscriptHex, long inputSatoshis);
```

### `runar.lang.sdk.WhatsOnChainProvider`

```java
public WhatsOnChainProvider();                            // mainnet, default transport
public WhatsOnChainProvider(String network);              // "mainnet" | "testnet"

public String getNetwork();
public String getBaseUrl();

// Provider
public List<UTXO> listUtxos(String address);
public String broadcastRaw(String txHex);
public UTXO getUtxo(String txid, int vout);

// Extensions
public String getRawTransaction(String txid);
```

### `runar.lang.sdk.codegen.TypedContractGenerator`

```java
public static String generate(RunarArtifact artifact, String packageName);
```

### `runar.lang.sdk.ordinals.Bsv20`

```java
public static final String CONTENT_TYPE = "application/bsv-20";

public static Inscription deploy(String ticker, long maxSupply, long mintLimit, int decimals);
public static Inscription deploy(String ticker, String maxSupply, String mintLimit, String decimals);
public static Inscription mint(String ticker, long amount);
public static Inscription mint(String ticker, String amount);
public static Inscription transfer(String ticker, long amount);
public static Inscription transfer(String ticker, String amount);

public static Op parse(byte[] inscription);
public static Op parse(String json);

public record Op(
    String p, String op, String tick,
    String max, String lim, String dec, String amt) {}
```

### `runar.lang.sdk.ordinals.Bsv21`

```java
public static Inscription deploy(String symbol, long initialSupply, String tokenId);
public static Inscription deployMint(String amount, String decimals, String symbol, String icon);
public static Inscription transfer(String tokenId, long amount);
public static Inscription transfer(String tokenId, String amount);

public static Op parse(byte[] inscription);
public static Op parse(String json);

public record Op(
    String p, String op, String id,
    String sym, String dec, String icon, String amt) {}
```

### `runar.lang.sdk.ordinals.TokenWallet`

```java
public TokenWallet(RunarArtifact artifact, Provider provider, Signer signer);

public RunarArtifact getArtifact();
public Provider getProvider();
public Signer getSigner();

public List<UTXO> getUtxos();
public static UTXO pickCandidate(List<UTXO> candidates);
```

---

## 16. Error handling

The SDK uses checked exceptions where the JDK does
(`CompileCheck.run(Path)` throws `IOException`), and
`RuntimeException`-derived classes for everything that's a programming
or environmental failure.

| Exception                                  | Thrown by                                            | Recovery                                      |
|--------------------------------------------|------------------------------------------------------|-----------------------------------------------|
| [`CompileException`](src/main/java/runar/lang/sdk/CompileException.java) | `CompileCheck.run`, `CompileCheck.check` | Inspect `errors()` for the structured error list. Fix the contract source. |
| [`ProviderException`](src/main/java/runar/lang/sdk/ProviderException.java) | `RPCProvider`, `WhatsOnChainProvider`, `GorillaPoolProvider`, `WalletProvider` | Inspect `statusCode()` (HTTP status, or `0` for transport errors). Retry transient failures; surface protocol errors. |
| `IllegalArgumentException`                 | Constructors and method preconditions throughout the SDK | Programming error — fix the call site.       |
| `IllegalStateException`                    | `RunarContract.call` / `prepareCall` before deploy; insufficient funds in `TransactionBuilder` | Programming error or insufficient funds.     |
| `AssertionError`                           | `Builtins.assertThat`; contract-internal asserts under the simulator | The contract rejected the input. Adjust args. |
| `AnfInterpreter.AssertionFailureException` | `AnfInterpreter.executeStrict` when an assert binding fails | Same as above, but for ANF-IR-driven simulation. |
| `AnfInterpreter.InterpreterException`      | Missing or malformed ANF IR                          | Re-compile to regenerate the artifact JSON.  |
| `UnsupportedOperationException`            | `Builtins.*` outside the simulator; ANF interpreter on Go-only crypto primitives | Wrap the call in `ContractSimulator`, or test via the compiler+VM path. |
| `IOException`                              | `CompileCheck.run(Path)`                             | Standard JDK file I/O recovery.              |

### Catching frontend errors

```java
try {
    CompileCheck.run(Path.of("Counter.runar.java"));
} catch (CompileException ce) {
    for (String err : ce.errors()) {
        System.err.println("  " + err);
    }
} catch (IOException ioe) {
    System.err.println("cannot read file: " + ioe.getMessage());
}
```

### Catching provider errors

```java
try {
    provider.broadcastRaw(txHex);
} catch (ProviderException pe) {
    if (pe.statusCode() == 503) {
        // transient — retry with backoff
    } else {
        throw pe;
    }
}
```

---

## 17. Troubleshooting / FAQ

**"My contract method throws `UnsupportedOperationException` from
`Builtins.checkSig`."**

You're calling the contract method directly from a `@Test` method
without going through `ContractSimulator`. The Builtins are
compile-time intrinsics; they only have a runtime body inside the
simulator. Wrap the call:

```java
ContractSimulator.stateless(myContract).call("unlock", sig, pub);
```

**"`RunarContract.call` throws `IllegalStateException: contract has not
been deployed`."**

Either call `deploy(provider, signer, satoshis)` first, or
`setCurrentUtxo(provider.getUtxo(txid, vout))` if reattaching to an
already-deployed contract.

**"`finalizeCall` throws `signature is not a DER sequence`."**

Each entry in the `signatures` list must start with the DER tag byte
`0x30`. Most signing libraries emit DER by default; if your wallet
returns raw `(r, s)`, run them through BouncyCastle's `DERSequence`
first (see `LocalSigner.derEncode`).

**"How do I write a new `Provider`?"**

Implement the four-method `Provider` interface and pass it to
`RunarContract.deploy` / `RunarContract.call`. For HTTP-backed
providers, mimic the test pattern in `RPCProviderTest` to inject a fake
`HttpTransport`.

**"My deployed locking script doesn't match what the TS SDK produces."**

It should — there are conformance tests that prove byte-identity. If
you have a divergence, file an issue with: the artifact JSON, the
constructor args, both rendered scripts, and the TS SDK version. Likely
suspects are number encoding (script-number vs. push-data) for
constructor args that crossed the 16-or-less / negative threshold.

**"Why does `WalletProvider` implement both `Provider` and
`ExternalSigner`?"**

Pragmatic fit. BRC-100 wallets typically expose both an outpoint store
and signing, and the Java SDK collapses the two roles into one adapter
so callers can pass `wp` for both `Provider` and `Signer` parameters.
The other six SDKs split them into a `WalletProvider` + `WalletSigner`
pair — there's no semantic difference, just a different shape.

**"Can I use this from Kotlin / Scala / Clojure?"**

Yes. `runar-java` is a regular JVM library targeting JDK 17 bytecode.
Kotlin coroutines / Scala futures can wrap the synchronous
`RunarContract.call` calls if you need async I/O patterns at the host
language level.

**"My `MockProvider`-driven test broadcasts succeed but the txid looks
fake."**

That's by design — `MockProvider.broadcastRaw` returns a deterministic
mock 64-char hex string (FNV-style hash of broadcast count + txhex
prefix). It exists so unit tests can pin exact strings; switch to
`RPCProvider` for real txids.

**"How do I run integration tests without a node?"**

You don't — they're gated behind `-Drunar.integration=true` exactly so
plain `gradle test` in CI without a node is a no-op. The
`@EnabledIfSystemProperty` guard on `IntegrationBase` does this.

**"Where are the `BSV-20` / `BSV-21` send/receive flows?"**

The `Bsv20` / `Bsv21` classes produce inscription envelopes; attach one
to a `RunarContract` via `withInscription(...)` to deploy a token
output. `TokenWallet.getUtxos()` filters a signer's UTXO set down to
those matching the artifact's locking-script prefix. Full transfer /
merge flows are caller-orchestrated using the standard `call(...)`
surface — see `examples/java/.../bsv21-token/` for a worked example.

---

## 18. Versioning and stability

The SDK follows the project-wide `runar-vX.Y.Z` versioning scheme
shared with the compiler artifacts. Cross-SDK conformance is enforced:
all seven SDKs (TS, Go, Rust, Python, Java, Ruby, Zig) at the same
version must produce byte-identical deployed locking scripts for the
same artifact + constructor args (see `conformance/sdk-output/`).

Stability tiers:

- **Stable** (semver: breaking changes bumped at the minor level until
  1.0): `RunarContract`, `RunarArtifact`, `Provider`, `Signer`,
  `LocalSigner`, `MockProvider`, `MockSigner`, `WalletProvider`,
  `BRC100Wallet`, `Inscription`, `UTXO`, `PreparedCall`,
  `CompileCheck`, `CompileException`, `ProviderException`,
  `StateSerializer`, `FeeEstimator`, `UtxoSelector`,
  `TransactionBuilder`, `RPCProvider`, `WhatsOnChainProvider`,
  `GorillaPoolProvider`, `Bsv20`, `Bsv21`, `TokenWallet`,
  `runar.lang.SmartContract`, `runar.lang.StatefulSmartContract`,
  `runar.lang.Builtins`, the `runar.lang.types` family, and the
  `runar.lang.annotations` annotations.
- **Stable but evolving**: `TypedContractGenerator` — the wrapper-class
  shape may grow new accessors (e.g. typed `Provider` / `Signer`
  swapping helpers) at minor versions. Generated source is regenerated
  on each version bump, so consumers should treat the output as a build
  artifact, not a checked-in source file.
- **Internal**: `ContractScript`, `ScriptUtils`, `RawTx`,
  `RawTxParser`, `OpPushTx`, `Hash160`, `Base58Check`, `Json`,
  `JsonWriter`, `HttpTransport`. Package-private or
  `static`-but-undocumented; subject to change without notice.

Removed surfaces are tagged `@Deprecated` for one minor cycle before
deletion. Behavioural changes that affect generated locking-script
bytes are bumped at the major level.

---

## 19. Links

- Project root: [`../../README.md`](../../README.md)
- Language specification: [`../../spec/`](../../spec)
- Java compiler frontend: [`../../compilers/java/`](../../compilers/java)
- Java contract examples: [`../../examples/java/`](../../examples/java)
- Java integration tests: [`../../integration/java/`](../../integration/java)
- Cross-SDK conformance suite: [`../../conformance/sdk-output/`](../../conformance/sdk-output)
- Sibling SDKs:
  [`runar-sdk` (TS)](../runar-sdk),
  [`runar-go`](../runar-go),
  [`runar-rs`](../runar-rs),
  [`runar-py`](../runar-py),
  [`runar-zig`](../runar-zig),
  [`runar-rb`](../runar-rb)
- Format guide: [`../../docs/formats/java.md`](../../docs/formats/java.md)
