// ---------------------------------------------------------------------------
// runar-lang/runtime/contract.ts — Runtime-safe base classes
// ---------------------------------------------------------------------------
// Override the throwing methods with working implementations for off-chain use.
// ---------------------------------------------------------------------------

import type { ByteString, Addr } from '../types.js';
import { SmartContract as BaseSmartContract } from '../index.js';

export abstract class SmartContract extends BaseSmartContract {
  protected getStateScript(): ByteString {
    return '' as ByteString;
  }

  protected buildP2PKH(addr: Addr): ByteString {
    return ('76a914' + addr + '88ac') as ByteString;
  }
}

export abstract class StatefulSmartContract extends SmartContract {
  protected readonly txPreimage!: import('../types.js').SigHashPreimage;

  protected addOutput(_satoshis: bigint, ..._stateValues: unknown[]): void {
    // No-op in off-chain simulation
  }
}
