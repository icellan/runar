/**
 * Cross-format `asm({...})` + `UnsafeSmartContract` parity test.
 *
 * Verifies that a minimal `unlock` method calling `asm({body:'51', in_arity:0,
 * out_arity:1})` compiles to the same single-byte locking script (`51`,
 * i.e. OP_1) when authored in each of the 9 supported source formats. The
 * TypeScript-canonical `.runar.ts` form uses the object-literal asm() call;
 * the 8 peer formats use the positional `asm(body, in_arity, out_arity)`
 * shape that their parsers normalise into the same call_expr ANF lowering.
 *
 * This is the user-facing complement to `asm-surface.test.ts` (which only
 * exercises the .runar.ts form). It is the floor for the Phase-3 WS-1
 * cross-language asm contract: every frontend lowers `asm` to the same
 * raw_script ANF binding, and the emitter writes the body bytes verbatim.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

interface Case {
  fileName: string;
  source: string;
}

// Each contract has one stateless method `unlock` whose entire body is a
// terminal `asm` call with body=0x51 (OP_1), in_arity=0, out_arity=1.
const CASES: Case[] = [
  {
    fileName: 'Anyone.runar.ts',
    source: `
      import { UnsafeSmartContract, asm } from 'runar-lang';

      class Anyone extends UnsafeSmartContract {
        constructor() {
          super();
        }

        public unlock() {
          asm({ body: '51', in_arity: 0, out_arity: 1 });
        }
      }
    `,
  },
  {
    fileName: 'Anyone.runar.sol',
    source: `
contract Anyone is UnsafeSmartContract {
    constructor() {}
    function unlock() public {
        asm(0x51, 0, 1);
    }
}
`,
  },
  {
    fileName: 'Anyone.runar.move',
    source: `
unsafe module Anyone {
    public fun unlock() {
        asm(0x51, 0, 1);
    }
}
`,
  },
  {
    fileName: 'Anyone.runar.go',
    source: `package contract
import runar "github.com/icellan/runar/packages/runar-go"

type Anyone struct {
    runar.UnsafeSmartContract
}

func (c *Anyone) Unlock() {
    runar.Asm("51", 0, 1)
}
`,
  },
  {
    fileName: 'Anyone.runar.rs',
    source: `use runar::prelude::*;

#[runar::unsafe_contract]
pub struct Anyone {}

impl Anyone {
    pub fn unlock(&self) {
        asm("51", 0, 1);
    }
}
`,
  },
  {
    fileName: 'Anyone.runar.py',
    source: `from runar import UnsafeSmartContract, public, asm

class Anyone(UnsafeSmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self):
        asm("51", 0, 1)
`,
  },
  {
    fileName: 'Anyone.runar.zig',
    source: `const runar = @import("runar");

pub const Anyone = struct {
    pub const Contract = runar.UnsafeSmartContract;

    pub fn init() Anyone {
        return .{};
    }

    pub fn unlock(self: *const Anyone) void {
        _ = self;
        runar.asm("51", 0, 1);
    }
};
`,
  },
  {
    fileName: 'Anyone.runar.rb',
    source: `require 'runar'

class Anyone < Runar::UnsafeSmartContract
  def initialize
    super()
  end

  runar_public
  def unlock
    asm("51", 0, 1)
  end
end
`,
  },
  {
    fileName: 'Anyone.runar.java',
    source: `package runar.examples.anyone;

import runar.lang.UnsafeSmartContract;
import runar.lang.annotations.Public;
import static runar.lang.Builtins.asm;

class Anyone extends UnsafeSmartContract {
    Anyone() {
        super();
    }

    @Public
    void unlock() {
        asm("51", 0, 1);
    }
}
`,
  },
];

describe('asm({...}) cross-format parity — UnsafeSmartContract + asm in all 9 formats', () => {
  for (const c of CASES) {
    it(`compiles ${c.fileName} to scriptHex '51'`, () => {
      const result = compile(c.source, { fileName: c.fileName });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors, errors.map(d => d.message).join('\n')).toEqual([]);
      expect(result.success).toBe(true);
      expect(result.scriptHex).toBe('51');
      expect(result.contract).not.toBeNull();
      expect(result.contract!.parentClass).toBe('UnsafeSmartContract');
    });
  }
});
