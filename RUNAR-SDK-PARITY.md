# Rúnar SDK Parity

The seven deployment SDKs — `packages/runar-{sdk (TypeScript), go, rs, py, zig, rb, java}` —
are independent implementations of the same on-chain surface (deploy / call /
state-serialize / sign / verify). This document records what must stay
byte-identical across them and where that parity is enforced.

## What requires cross-tier parity (wire-protocol bytes)

Anything whose bytes cross a tier boundary MUST be byte-identical across all
seven SDKs:

- **`canonicalJson`** — RFC 8785 / JCS-compliant serializer used to hash payloads
  before signing. Divergent bytes silently break every cross-tier signature.
- **`SignedEnvelope` + `signEnvelope` + `verifyEnvelope`** — the signed-broadcast
  wire protocol. Every SDK must accept the same envelope shape, produce
  signatures verifiable by every other tier, and return the same
  `VerifyEnvelopeReason` for the same rejection case.
- **Deployed locking script bytes** — the same compiled artifact + constructor
  args must produce the same locking script from every SDK.
- **BIP-143 sighash preimage** — recomputed identically in every tier.

Convenience wrappers around tier-local primitives (`pubkeyToPKH`,
`estimateFeeForArtifact`, `LocalSigner`, provider classes, and the SDK codegen
helpers such as `Runar::SDK::CodeGen`) are per-tier ergonomic surface and do
**not** require API-shape parity — only the wire bytes are synchronized.

## Where parity is enforced (conformance)

| Suite | Enforces |
|---|---|
| `conformance/sdk-output/` | All seven SDKs produce identical deployed locking-script hex for each fixture. |
| `conformance/sdk-codegen/` | SDK codegen surface fixtures (the TS/Go/Rust/Python/… runners). |
| `conformance/sdk-envelope/` | A TS-signed `SignedEnvelope` fixture + a known-bad envelope per rejection reason, replayed against every tier's `verifyEnvelope`. |
| `conformance/sdk-bip143/` | Cross-tier BIP-143 preimage recomputation. |

Any change to a wire-protocol primitive must round-trip through these suites.
CI runs them as blocking gates (see `.github/workflows/ci.yml`).

## Codegen naming

The Ruby SDK exposes `Runar::SDK::CodeGen` (canonical camel-case). Older code and
docs may reference `Runar::SDK::Codegen`; both spellings resolve. The canonical
name across the tree is `CodeGen`.
