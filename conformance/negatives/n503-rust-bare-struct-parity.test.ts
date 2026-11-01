import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-503 — a `.runar.rs` struct with no `#[runar::contract]` /
 * `#[runar::stateful_contract]` / `#[runar::unsafe_contract]` attribute is not
 * a contract, in every tier.
 *
 * docs/formats/rust.md: "Contracts are Rust structs annotated with
 * `#[runar::contract]`". Go, Rust, Python, Zig and Java already refused a bare
 * struct ("no Rúnar contract struct found in Rust source"); the TS reference
 * and Ruby instead promoted ANY struct to the contract, so a bare helper
 * struct declared AFTER the real contract (docs/formats/rust.md's `FtOutput`
 * pattern) silently replaced it.
 *
 * What this proves:
 *   - a bare stateless struct and a bare mutable-field struct (with an impl)
 *     are refused by every available tier with the shared diagnostic;
 *   - an attributed contract followed by a bare helper struct compiles to the
 *     same hex on every tier, equal to the same contract without the helper.
 * What it does NOT prove:
 *   - the exact position prefix of the diagnostic (differs per tier);
 *   - helper structs that carry their own `#[runar::...]` attribute, or
 *     multiple attributed structs in one file (a separate question).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n503-'));
const DIAG = 'no Rúnar contract struct found in Rust source';

const IMPL = `
impl Check {
    pub fn unlock(&self, x: Bigint) {
        assert!(x == self.target);
    }
}
`;

const attrStruct = `use runar::prelude::*;

#[runar::contract]
pub struct Check {
    #[readonly]
    pub target: Bigint,
}
`;

const bareStateless = `use runar::prelude::*;

pub struct Check {
    #[readonly]
    pub target: Bigint,
}
${IMPL}`;

const bareStateful = `use runar::prelude::*;

pub struct Counter {
    pub count: Bigint,
}

impl Counter {
    pub fn bump(&mut self) {
        self.count = self.count + 1;
    }
}
`;

const helper = `
#[derive(Clone)]
pub struct Helper {
    pub amount: Bigint,
}
`;

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

describe('N-503 bare struct in .runar.rs — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, file, text] of [
    ['stateless', 'Check.runar.rs', bareStateless],
    ['mutable fields', 'Counter.runar.rs', bareStateful],
  ] as const) {
    const path = write(file, text);
    for (const tier of TIERS) {
      it(`${tier.id} refuses a bare ${name} struct`, () => {
        const j = judge(tier, path);
        expect(j.verdict).toBe('rejected');
        expect(j.diag).toContain(DIAG);
      });
    }
  }

  const base = write('Check.runar.rs', attrStruct + IMPL);
  const withTrailing = write('Check.runar.rs', attrStruct + IMPL + helper);
  const withLeading = write('Check.runar.rs', helper + attrStruct + IMPL);
  for (const [name, path] of [['trailing', withTrailing], ['leading', withLeading]] as const) {
    it(`every tier ignores a ${name} bare helper struct and compiles the same hex`, () => {
      const want = compileHex(TIERS[0]!, base);
      for (const t of TIERS) expect(compileHex(t, path)).toBe(want);
    });
  }
});
