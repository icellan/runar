import { UnsafeSmartContract, asm } from 'runar-lang';

/**
 * Anyone — minimal `asm` raw-script contract.
 *
 * Compiles to a single byte (`0x51`, OP_1) locking script that anyone can
 * spend. Exists to exercise the `asm({...})` intrinsic and
 * `UnsafeSmartContract` parent class across all 9 source formats.
 */
class Anyone extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock() {
    asm({ body: '51', in_arity: 0, out_arity: 1 });
  }
}
