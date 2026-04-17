// ---------------------------------------------------------------------------
// runar-sdk/ordinals/bsv20.ts — BSV-20 and BSV-21 token inscription helpers
// ---------------------------------------------------------------------------
//
// BSV-20 (v1): tick-based fungible tokens. "First is first" for ticker.
// BSV-21 (v2): ID-based (txid_vout), admin-controlled distribution.
//
// Both use content type "application/bsv-20" with JSON payloads.
// ---------------------------------------------------------------------------

import type { Inscription } from './types.js';

/** Convert a UTF-8 string to hex. */
function utf8ToHex(str: string): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function jsonInscription(obj: Record<string, string>): Inscription {
  return {
    contentType: 'application/bsv-20',
    data: utf8ToHex(JSON.stringify(obj)),
  };
}

// ---------------------------------------------------------------------------
// BSV-20 (v1) — tick-based fungible tokens
// ---------------------------------------------------------------------------

export interface BSV20DeployParams {
  tick: string;
  max: string;
  lim?: string;
  dec?: string;
}

export interface BSV20MintParams {
  tick: string;
  amt: string;
}

export interface BSV20TransferParams {
  tick: string;
  amt: string;
}

export const BSV20 = {
  /**
   * Build a BSV-20 deploy inscription.
   *
   * ```ts
   * BSV20.deploy({ tick: 'RUNAR', max: '21000000', lim: '1000' })
   * ```
   */
  deploy(params: BSV20DeployParams): Inscription {
    const obj: Record<string, string> = {
      p: 'bsv-20',
      op: 'deploy',
      tick: params.tick,
      max: params.max,
    };
    if (params.lim !== undefined) obj.lim = params.lim;
    if (params.dec !== undefined) obj.dec = params.dec;
    return jsonInscription(obj);
  },

  /**
   * Build a BSV-20 mint inscription.
   *
   * ```ts
   * BSV20.mint({ tick: 'RUNAR', amt: '1000' })
   * ```
   */
  mint(params: BSV20MintParams): Inscription {
    return jsonInscription({
      p: 'bsv-20',
      op: 'mint',
      tick: params.tick,
      amt: params.amt,
    });
  },

  /**
   * Build a BSV-20 transfer inscription.
   *
   * ```ts
   * BSV20.transfer({ tick: 'RUNAR', amt: '50' })
   * ```
   */
  transfer(params: BSV20TransferParams): Inscription {
    return jsonInscription({
      p: 'bsv-20',
      op: 'transfer',
      tick: params.tick,
      amt: params.amt,
    });
  },
};

// ---------------------------------------------------------------------------
// BSV-21 (v2) — ID-based fungible tokens
// ---------------------------------------------------------------------------

export interface BSV21DeployMintParams {
  amt: string;
  dec?: string;
  sym?: string;
  icon?: string;
}

export interface BSV21TransferParams {
  id: string;
  amt: string;
}

export const BSV21 = {
  /**
   * Build a BSV-21 deploy+mint inscription.
   *
   * The token ID will be `<txid>_<vout>` of the output containing
   * this inscription once broadcast.
   *
   * ```ts
   * BSV21.deployMint({ amt: '1000000', dec: '18', sym: 'RNR' })
   * ```
   */
  deployMint(params: BSV21DeployMintParams): Inscription {
    const obj: Record<string, string> = {
      p: 'bsv-20',
      op: 'deploy+mint',
      amt: params.amt,
    };
    if (params.dec !== undefined) obj.dec = params.dec;
    if (params.sym !== undefined) obj.sym = params.sym;
    if (params.icon !== undefined) obj.icon = params.icon;
    return jsonInscription(obj);
  },

  /**
   * Build a BSV-21 transfer inscription.
   *
   * ```ts
   * BSV21.transfer({ id: '3b313338fa05...0000_1', amt: '100' })
   * ```
   */
  transfer(params: BSV21TransferParams): Inscription {
    return jsonInscription({
      p: 'bsv-20',
      op: 'transfer',
      id: params.id,
      amt: params.amt,
    });
  },
};
