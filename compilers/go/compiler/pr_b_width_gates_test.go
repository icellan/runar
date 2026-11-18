package compiler

import (
	"strings"
	"testing"
)

// #180 / #213 / D13: a public method's fixed-width parameter is pinned to its
// declared width at entry (`<copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP`),
// except a PubKey that only ever reaches checkSig / checkMultiSig / hash160.
// Port of the TypeScript reference pins (05-stack-lower.ts,
// emitFixedWidthParamGate / paramNeedsWidthGate). The expected bytes are the
// TS tier's output for the same sources, in both fold modes.

const prbLockSrc = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { Point } from 'runar-lang';
class Lock extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public lock(p: Point) {
    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`

const prbPayToKeySrc = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class PayToKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`

const prbP2PKHSrc = `import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`

const prbHelperP2PKHSrc = `import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';
class HelperP2PKH extends SmartContract {
  readonly pkh: Addr;
  constructor(pkh: Addr) { super(pkh); this.pkh = pkh; }
  private verify(s: Sig, k: PubKey): boolean { return checkSig(s, k); }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pkh);
    assert(this.verify(sig, pubKey));
  }
}
`

func prbCompileHex(t *testing.T, src, fileName string, disableFold bool) string {
	t.Helper()
	res := CompileFromSourceStrWithResult(src, fileName, CompileOptions{DisableConstantFolding: disableFold})
	if !res.Success {
		t.Fatalf("%s (disableFold=%v): compile failed: %v", fileName, disableFold, res.Diagnostics)
	}
	return strings.ToLower(res.ScriptHex)
}

// prbCountAligned counts occurrences of sub that start on a byte boundary.
func prbCountAligned(hexStr, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(hexStr); i += 2 {
		if hexStr[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}

func TestPRB_PointParamAndChangePKHAreWidthGated(t *testing.T) {
	for _, disable := range []bool{true, false} {
		h := prbCompileHex(t, prbLockSrc, "Lock.runar.ts", disable)
		if !strings.Contains(h, "5379820140"+"9d75"+"5279820114"+"9d75") {
			t.Errorf("disableFold=%v: missing Point + _changePKH entry gates: %s", disable, h)
		}
		for _, gate := range []string{"8201409d", "8201149d"} {
			if c := prbCountAligned(h, gate); c != 1 {
				t.Errorf("disableFold=%v: %s occurs %d times, want 1", disable, gate, c)
			}
		}
	}
}

func TestPRB_SplicedPubKeyIsWidthGated(t *testing.T) {
	for _, disable := range []bool{true, false} {
		h := prbCompileHex(t, prbPayToKeySrc, "PayToKey.runar.ts", disable)
		if !strings.Contains(h, "5379820121"+"9d75") {
			t.Errorf("disableFold=%v: missing PubKey entry gate: %s", disable, h)
		}
		if c := prbCountAligned(h, "8201219d"); c != 1 {
			t.Errorf("disableFold=%v: 8201219d occurs %d times, want 1", disable, c)
		}
	}
}

func TestPRB_P2PKHStaysOnStandardTemplate(t *testing.T) {
	for _, disable := range []bool{true, false} {
		if h := prbCompileHex(t, prbP2PKHSrc, "P2PKH.runar.ts", disable); h != "76a90088ac" {
			t.Errorf("disableFold=%v: P2PKH = %s, want 76a90088ac", disable, h)
		}
	}
}

func TestPRB_PubKeyVerifiedThroughPrivateHelperIsNotGated(t *testing.T) {
	for _, disable := range []bool{true, false} {
		h := prbCompileHex(t, prbHelperP2PKHSrc, "HelperP2PKH.runar.ts", disable)
		if strings.Contains(h, "8201219d") {
			t.Errorf("disableFold=%v: verified-only PubKey must not be gated: %s", disable, h)
		}
	}
}

const prbPickKeySrc = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class PickKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public pay(pick: boolean, a: PubKey, b: PubKey) {
    const k = pick ? a : b;
    this.addRawOutput(1000n, cat(cat(toByteString('21'), k), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`

const prbIdKeySrc = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class IdKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  private id(k: PubKey): PubKey { return k; }
  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), this.id(pk)), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`

func TestPRB_PubKeyThroughTernaryArmIsWidthGated(t *testing.T) {
	for _, disable := range []bool{true, false} {
		h := prbCompileHex(t, prbPickKeySrc, "PickKey.runar.ts", disable)
		if c := prbCountAligned(h, "8201219d"); c != 2 {
			t.Errorf("disableFold=%v: 8201219d occurs %d times, want 2: %s", disable, c, h)
		}
	}
}

func TestPRB_PubKeyReturnedByPrivateHelperIsWidthGated(t *testing.T) {
	for _, disable := range []bool{true, false} {
		h := prbCompileHex(t, prbIdKeySrc, "IdKey.runar.ts", disable)
		if c := prbCountAligned(h, "8201219d"); c != 1 {
			t.Errorf("disableFold=%v: 8201219d occurs %d times, want 1: %s", disable, c, h)
		}
	}
}

const prbMergedKeySrc = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class MergedKey extends StatefulSmartContract {
  closed: bigint = 0n;
  k: PubKey = "000000000000000000000000000000000000000000000000000000000000000000" as PubKey;
  amt: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.closed = seed; }
  public bid(bidderKey: PubKey, bidAmount: bigint) {
    assert(this.closed === 0n);
    let nk = this.k;
    let namt = this.amt;
    if (this.amt === 0n) { nk = bidderKey; namt = bidAmount; }
    else { nk = bidderKey; namt = bidAmount + 1n; }
    this.addOutput(bidAmount, this.closed, nk, namt);
  }
}
`

func TestPRB_CyclicMergedLocalAliasTerminatesAndIsGated(t *testing.T) {
	for _, disable := range []bool{true, false} {
		h := prbCompileHex(t, prbMergedKeySrc, "MergedKey.runar.ts", disable)
		if !strings.Contains(h, "5479820121"+"9d75") {
			t.Errorf("disableFold=%v: missing entry gate: %s", disable, h)
		}
		if c := prbCountAligned(h, "8201219d"); c != 2 {
			t.Errorf("disableFold=%v: 8201219d occurs %d times, want 2: %s", disable, c, h)
		}
	}
}
