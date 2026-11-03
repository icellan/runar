import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';

/**
 * N-002 (CL-BUG-214, the cross-tier half of F-013) — an index assignment is
 * only a write when its root is a FixedArray contract property.
 *
 * 03b-expand-fixed-arrays rewrites `this.arr[i] = v` only when `arr` is a
 * FixedArray property. Every other index target — `this.blob[0n] = 7n` on a
 * ByteString property, `c[0n] = 7n` on a local, `b[0n] = 7n` on a parameter,
 * a member-chained root — survived to ANF lowering, which lowered the target
 * as a READ and dropped the value. The result was a deployable script with no
 * diagnostic whose state never changes: measured on `@bsv/sdk`
 * `Spend.validate()`, the pre-fix artifact of F-013's Blob.runar.ts (script
 * `61ab7676aa517f…`) accepted a continuation carrying the UNCHANGED blob, and
 * the parameter shape `b[0n] = 7n; assert(b == this.h)` accepted `b == h`,
 * which the source's post-write assertion rejects (see
 * remediation-logs/N-002/exec-proof*.txt).
 *
 * The rule and its diagnostic are F-013's Python rule, verbatim, applied in
 * the validator so every surface (they all lower to the same AST) is covered.
 *
 * What this proves: the reference tier refuses, with the shared diagnostic
 * and a source location, a non-FixedArray index write on all nine surfaces
 * (ByteString property, local, parameter), plus the compound, nested,
 * member-chained and runtime-index spellings on the TS surface; FixedArray
 * index writes (literal, runtime, compound, `++`, nested literal) still
 * validate and compile.
 * What it does NOT prove: the other six tiers (their own suites and
 * conformance/negatives/N81-N94 cover that), byte-identity of the FixedArray
 * goldens (the conformance golden + multi-format runs do), or any semantics
 * for byte-level writes into a ByteString, which Rúnar does not define.
 */

const NEEDLE =
  'index assignment is only supported on FixedArray contract properties; ' +
  'the target here is not a FixedArray property';

function validationErrors(source: string, fileName: string) {
  const p = parse(source, fileName);
  expect(p.contract, `${fileName} failed to parse: ${p.errors.map((e) => e.message).join('; ')}`).toBeTruthy();
  return validate(p.contract!).errors;
}

function expectRefused(source: string, fileName: string, count = 1): void {
  const hits = validationErrors(source, fileName).filter((e) => e.message === NEEDLE);
  expect(hits.length, `${fileName}: expected ${count} '${NEEDLE}' error(s)`).toBe(count);
  for (const h of hits) expect(h.loc?.line ?? 0, `${fileName}: diagnostic carries no location`).toBeGreaterThan(0);
  const r = compile(source, { fileName });
  expect(r.success, `${fileName} compiled a script that silently drops the write`).toBe(false);
  expect(r.diagnostics.map((d) => d.message)).toContain(NEEDLE);
}

// ---------------------------------------------------------------------------
// TypeScript surface: every shape
// ---------------------------------------------------------------------------

function blob(body: string): string {
  return `import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class Blob extends StatefulSmartContract {
  blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public poke(i: bigint) {
    ${body}
    assert(true);
  }
}
`;
}

const TS_LOCAL = `import { SmartContract, ByteString, assert } from 'runar-lang';

class Loc extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    let c: ByteString = b;
    c[0n] = 7n;
    assert(c == this.h);
  }
}
`;

const TS_PARAM = `import { SmartContract, ByteString, assert } from 'runar-lang';

class Par extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    b[0n] = 7n;
    assert(b == this.h);
  }
}
`;

describe('N-002: TS surface refuses a non-FixedArray index write', () => {
  const shapes: Array<[string, string]> = [
    ['ByteString property, literal index', blob('this.blob[0n] = 7n;')],
    ['ByteString property, runtime index', blob('this.blob[i] = 7n;')],
    ['ByteString property, +=', blob('this.blob[0n] += 7n;')],
    ['ByteString property, -=', blob('this.blob[0n] -= 7n;')],
    ['ByteString property, *=', blob('this.blob[0n] *= 7n;')],
    ['ByteString property, /=', blob('this.blob[0n] /= 7n;')],
    ['ByteString property, %=', blob('this.blob[0n] %= 7n;')],
    ['ByteString property, nested index', blob('this.blob[0n][1n] = 7n;')],
    ['member-chained root', blob('this.blob.x[0n] = 7n;')],
    ['local', TS_LOCAL],
    ['parameter', TS_PARAM],
  ];
  for (const [name, src] of shapes) {
    it(name, () => expectRefused(src, 'Blob.runar.ts'));
  }
});

// ---------------------------------------------------------------------------
// Every other surface: the ByteString-property write, and local + parameter
// ---------------------------------------------------------------------------

const SURFACE_PROP: Record<string, string> = {
  'Blob.runar.sol': `pragma runar ^0.1.0;

contract Blob is StatefulSmartContract {
    ByteString blob;

    constructor(ByteString _blob) {
        blob = _blob;
    }

    function poke() public {
        this.blob[0] = 7;
        require(true);
    }
}
`,
  'Blob.runar.move': `module Blob {
    use runar::types::{ByteString};

    resource struct Blob {
        blob: &mut ByteString,
    }

    public fun poke(contract: &mut Blob) {
        contract.blob[0] = 7;
        assert!(true, 0);
    }
}
`,
  'Blob.runar.go': `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Blob struct {
\trunar.StatefulSmartContract
\tBlob runar.ByteString
}

func (c *Blob) Poke() {
\tc.Blob[0] = 7
\trunar.Assert(true)
}
`,
  'Blob.runar.rs': `use runar::prelude::*;

#[runar::contract]
pub struct Blob {
    pub blob: ByteString,
}

impl Blob {
    pub fn poke(&mut self) {
        self.blob[0] = 7;
        assert!(true);
    }
}
`,
  'Blob.runar.py': `from runar import StatefulSmartContract, ByteString, public, assert_


class Blob(StatefulSmartContract):
    blob: ByteString

    def __init__(self, blob: ByteString):
        super().__init__(blob)
        self.blob = blob

    @public
    def poke(self):
        self.blob[0] = 7
        assert_(True)
`,
  'Blob.runar.zig': `const runar = @import("runar");

pub const Blob = struct {
    pub const Contract = runar.StatefulSmartContract;

    blob: runar.ByteString = "",

    pub fn init(blob: runar.ByteString) Blob {
        return .{ .blob = blob };
    }

    pub fn poke(self: *Blob) void {
        self.blob[0] = 7;
        runar.assert(true);
    }
};
`,
  'Blob.runar.rb': `require 'runar'

class Blob < Runar::StatefulSmartContract
  prop :blob, ByteString

  def initialize(blob)
    super(blob)
    @blob = blob
  end

  runar_public
  def poke
    @blob[0] = 7
    assert true
  end
end
`,
  'Blob.runar.java': `package runar.examples.blob;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

class Blob extends StatefulSmartContract {

    ByteString blob;

    Blob(ByteString blob) {
        super(blob);
        this.blob = blob;
    }

    @Public
    void poke() {
        this.blob[0] = 7;
        assertThat(true);
    }
}
`,
};

/** One local write (`c[0] = 7`) and one parameter write (`b[1] = 7`). */
const SURFACE_LOCAL_PARAM: Record<string, string> = {
  'Loc.runar.sol': `pragma runar ^0.1.0;

contract Loc is SmartContract {
    ByteString immutable h;

    constructor(ByteString _h) {
        h = _h;
    }

    function unlock(ByteString b) public {
        ByteString c = b;
        c[0] = 7;
        b[1] = 7;
        require(c == this.h);
    }
}
`,
  'Loc.runar.move': `module Loc {
    use runar::types::{ByteString};

    struct Loc {
        h: ByteString,
    }

    public fun unlock(contract: &Loc, b: ByteString) {
        let c: ByteString = b;
        c[0] = 7;
        b[1] = 7;
        assert!(c == contract.h, 0);
    }
}
`,
  'Loc.runar.go': `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Loc struct {
\trunar.SmartContract
\tH runar.ByteString \`runar:"readonly"\`
}

func (c *Loc) Unlock(b runar.ByteString) {
\td := b
\td[0] = 7
\tb[1] = 7
\trunar.Assert(d == c.H)
}
`,
  'Loc.runar.rs': `use runar::prelude::*;

#[runar::contract]
pub struct Loc {
    #[readonly]
    pub h: ByteString,
}

impl Loc {
    pub fn unlock(&self, b: ByteString) {
        let c = b;
        c[0] = 7;
        b[1] = 7;
        assert!(c == self.h);
    }
}
`,
  'Loc.runar.py': `from runar import SmartContract, ByteString, public, assert_


class Loc(SmartContract):
    h: ByteString

    def __init__(self, h: ByteString):
        super().__init__(h)
        self.h = h

    @public
    def unlock(self, b: ByteString):
        c = b
        c[0] = 7
        b[1] = 7
        assert_(c == self.h)
`,
  'Loc.runar.zig': `const runar = @import("runar");

pub const Loc = struct {
    pub const Contract = runar.SmartContract;

    h: runar.ByteString,

    pub fn init(h: runar.ByteString) Loc {
        return .{ .h = h };
    }

    pub fn unlock(self: *const Loc, b: runar.ByteString) void {
        var c = b;
        c[0] = 7;
        b[1] = 7;
        runar.assert(runar.bytesEq(c, self.h));
    }
};
`,
  'Loc.runar.rb': `require 'runar'

class Loc < Runar::SmartContract
  prop :h, ByteString

  def initialize(h)
    super(h)
    @h = h
  end

  runar_public b: ByteString
  def unlock(b)
    c = b
    c[0] = 7
    b[1] = 7
    assert c == @h
  end
end
`,
  'Loc.runar.java': `package runar.examples.loc;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

class Loc extends SmartContract {

    @Readonly ByteString h;

    Loc(ByteString h) {
        super(h);
        this.h = h;
    }

    @Public
    void unlock(ByteString b) {
        ByteString c = b;
        c[0] = 7;
        b[1] = 7;
        assertThat(c.equals(this.h));
    }
}
`,
};

describe('N-002: every surface refuses a non-FixedArray index write', () => {
  for (const [fileName, src] of Object.entries(SURFACE_PROP)) {
    it(`${fileName}: ByteString property`, () => expectRefused(src, fileName));
  }
  for (const [fileName, src] of Object.entries(SURFACE_LOCAL_PARAM)) {
    it(`${fileName}: local + parameter`, () => expectRefused(src, fileName, 2));
  }
});

// ---------------------------------------------------------------------------
// The allowed case: FixedArray property index writes
// ---------------------------------------------------------------------------

const FIXED_ARRAY_WRITES = `import { StatefulSmartContract, FixedArray, assert } from 'runar-lang';

class Board extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set(i: bigint, v: bigint) {
    this.board[i] = v;
    this.board[0n] = v;
    this.board[1n] += v;
    this.board[2n]++;
    this.grid[0n][1n] = v;
    assert(true);
  }
}
`;

describe('N-002: FixedArray property index writes are still accepted', () => {
  it('literal, runtime, compound, ++ and nested literal writes validate and compile', () => {
    expect(validationErrors(FIXED_ARRAY_WRITES, 'Board.runar.ts').map((e) => e.message)).toEqual([]);
    const r = compile(FIXED_ARRAY_WRITES, { fileName: 'Board.runar.ts' });
    expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message)).toEqual([]);
    expect(r.success).toBe(true);
  });
});
