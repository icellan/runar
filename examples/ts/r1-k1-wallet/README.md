# R1-K1 Wallet

R1-K1 is a stateless wallet contract with two independent spending paths:

- **R1 primary:** a NIST P-256 (`secp256r1`) key generated inside a YubiKey's
  PIV application signs the current transaction's BIP-143 sighash.
- **K1 recovery:** a `secp256k1` key restored from an offline mnemonic and
  passphrase signs through Bitcoin's native `OP_CHECKSIG` path.

The locking script stores a salted R1 commitment and an ordinary K1 public-key
hash. The R1 salt is kept off-chain until it is supplied with the unlocking
witness. A public key is revealed when its corresponding path is used; neither
private key is ever placed on-chain.

## Security model

Either key can spend independently. The YubiKey is the convenient normal path,
but the recovery mnemonic is also a complete spending credential. Keep the
mnemonic and its passphrase offline, store them separately, and record the exact
derivation path. Compromise of the recovery material bypasses the YubiKey.

PIV touch proves that a person physically approved a signing operation; it does
not prove that the person reviewed the transaction. A YubiKey has no trusted
transaction display, so compromised host software could present a different
32-byte digest for approval. Transaction construction and digest display must
therefore be secured separately when that threat is in scope.

Each R1 salt must be unique, cryptographically random, and private until spend.
That keeps unspent commitments unlinkable even if the reused R1 public key is
otherwise known. An R1 spend reveals that output's public key and salt, but it
does not reveal the salts protecting other unspent outputs. Outputs become
linkable when their own R1 witnesses reveal the same public key. The salt is
privacy metadata rather than a substitute for a private signing key.

The salt is also required to use the R1 path. Back it up with the corresponding
output metadata. Losing it disables YubiKey spending for that output, although
the independent K1 recovery path remains available.

If the R1 key is generated on-device, it is non-exportable. Losing that YubiKey
is therefore irreversible for the R1 key itself, but the K1 path can still
recover the funds. Losing both credentials makes the output permanently
unspendable.

## Enrollment

1. Generate an `ECCP256` key inside a signing-capable YubiKey PIV slot, normally
   slot `9C`, with PIN and touch policies appropriate for the deployment.
2. Export only the P-256 public key and encode it as compressed SEC1
   (`02/03 || x`). Generate a unique cryptographically random 32-byte `r1Salt`
   for this output, store it privately with the output's recovery metadata,
   then compute
   `r1SaltedPubKeyHash = HASH160(compressedR1PubKey || r1Salt)`.
3. Create the recovery mnemonic and passphrase offline. Derive a dedicated
   secp256k1 child key using a documented wallet derivation path, then compute
   the compressed public key's `HASH160` as `k1PubKeyHash`.
4. Deploy `R1K1Wallet(r1SaltedPubKeyHash, k1PubKeyHash)` and verify both
   commitments against the enrollment records before funding it. Do not place
   `r1Salt` in the locking script. Generate a new R1 salt and commitment rather
   than reusing the locking script for another independently funded output.

## Normal R1 spend

Construct the spending transaction using `SIGHASH_ALL | SIGHASH_FORKID`
(`0x41`) and its BIP-143 preimage:

```text
sighash = SHA256(SHA256(txPreimage))
```

Send that exact 32-byte digest to the YubiKey PIV `GENERAL AUTHENTICATE: Sign`
operation. The YubiKey returns a DER ECDSA signature; convert its two integers
to fixed-width `r[32] || s[32]` form before calling:

```text
spendR1(r1Sig, r1PubKey, r1Salt, txPreimage)
```

The contract independently:

1. checks
   `HASH160(r1PubKey || r1Salt) == r1SaltedPubKeyHash`, revealing the salt only
   in this spend's unlocking witness;
2. pins the preimage's sighash type to `0x41`;
3. binds the preimage to the actual spending transaction with `checkPreimage`;
4. verifies the P-256 signature over the transaction's double-SHA-256 digest.

Avoid high-level PIV wrappers that hash the supplied digest a second time. The
low-level ECCP256 PIV signing operation accepts the 32-byte digest directly.

## K1 recovery

Restore the mnemonic with its passphrase, derive the recorded child key, and
produce a normal Bitcoin signature for the recovery transaction. Call:

```text
recoverK1(k1Sig, k1PubKey)
```

The contract checks the public-key commitment and executes `OP_CHECKSIG`.

## Deployment caveat

Rúnar currently implements P-256 verification with synthesized Bitcoin Script
elliptic-curve arithmetic. The existing P-256 wallet baseline is roughly
959 KB before this contract's preimage binding and method dispatch are added.
That exceeds the common 500,000-byte default script-size policy, so confirm the
target miner's current policy and run a real transaction-context spend test
before treating this example as deployable infrastructure.
