// N-105: a NUMBER in the scriptBytes position of `this.addRawOutput(...)`.
//
// The same shape as N16, one argument slot over — and this slot is the created
// output's LOCKING SCRIPT.
//
// The TypeScript reference refuses this source ("addRawOutput() second argument
// (scriptBytes) must be ByteString, got 'bigint'"); the other six tiers accepted
// it and spliced the number into the output serialization WITH NO CONVERSION.
// The emitted script was byte-identical to the same contract with
// `n: ByteString` — measured, not read: the bigint and ByteString twins both
// compiled through the Go tier to the same 1340-hexchar script, same digest, in
// all six accepting tiers.
//
// `lowerAddRawOutput` takes OP_SIZE of the operand, varint-prefixes it and
// concatenates it after the 8-byte amount. A script NUMBER on the stack is its
// minimal little-endian encoding, so the covenant commits to an output whose
// locking script IS those bytes. Executed on the real @bsv/sdk `Spend` engine
// against the exact 55-opcode window all six tiers emit:
//
//   n = 0    -> varint 0x00, locking script EMPTY          -> anyone-can-spend
//   n = 81   -> varint 0x01, locking script 0x51 = OP_1    -> anyone-can-spend
//   n = 118  -> varint 0x01, locking script 0x76 = OP_DUP  -> anyone-can-spend
//   n = 1000 -> varint 0x02, locking script 0xe8 0x03      -> 0xe8 is not a
//                                                             valid opcode, so
//                                                             the output can
//                                                             never be spent
//
// N16's failure mode was a wrong amount or a frozen UTXO. This one is worse in
// one direction: a small number in the scriptBytes slot produces an output that
// ANYONE can sweep, and the author never wrote a script at all. A type error in
// a covenant's script slot is a fund-loss bug, which is why this is a gate and
// not a lint.
//
// `addDataOutput` carries the identical second-argument contract and had the
// same hole in the same six tiers. Every tier routes both through ONE check, so
// this single source gates the pair here; the per-intrinsic probes live in each
// tier's own N-105 test.
//
// The shape stays invalid regardless of how inference evolves: `bigint` is not
// a subtype of `ByteString` under any tier's rule.
import { StatefulSmartContract, assert } from 'runar-lang';

export class NumberScriptBytes extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public bump(n: bigint) {
    assert(this.count >= 0n);
    this.count = this.count + 1n;
    this.addRawOutput(1000n, n);
  }
}
