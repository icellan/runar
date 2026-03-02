import { describe, it, expect } from 'vitest';
import { ScriptVM, decodeScriptNumber, hexToBytes, bytesToHex } from '../vm/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stackTopNum(hex: string): bigint {
  const vm = new ScriptVM();
  const result = vm.executeHex(hex);
  if (result.stack.length === 0) {
    throw new Error(`Stack is empty after executing: ${hex}`);
  }
  return decodeScriptNumber(result.stack[result.stack.length - 1]!);
}

// ---------------------------------------------------------------------------
// OP_ADD: OP_1 OP_1 OP_ADD = 0x51 0x51 0x93
// ---------------------------------------------------------------------------

describe('ScriptVM: arithmetic', () => {
  it('OP_1 OP_1 OP_ADD yields 2', () => {
    // OP_1 = 0x51, OP_ADD = 0x93
    const result = stackTopNum('515193');
    expect(result).toBe(2n);
  });

  it('OP_2 OP_3 OP_ADD yields 5', () => {
    // OP_2 = 0x52, OP_3 = 0x53, OP_ADD = 0x93
    const result = stackTopNum('525393');
    expect(result).toBe(5n);
  });

  it('OP_1 OP_1 OP_SUB yields 0', () => {
    // OP_SUB = 0x94
    const result = stackTopNum('515194');
    expect(result).toBe(0n);
  });

  it('OP_3 OP_2 OP_MUL yields 6', () => {
    // OP_MUL = 0x95
    const result = stackTopNum('535295');
    expect(result).toBe(6n);
  });
});

// ---------------------------------------------------------------------------
// OP_DUP OP_HASH160
// ---------------------------------------------------------------------------

describe('ScriptVM: DUP HASH160 pattern', () => {
  it('OP_DUP OP_HASH160 leaves two items on stack', () => {
    // Push 1 byte of data (0x01 = push 1 byte, 0xab = data), then OP_DUP (0x76), OP_HASH160 (0xa9)
    const vm = new ScriptVM();
    const result = vm.executeHex('01ab76a9');
    expect(result.stack.length).toBe(2);
    // First item is the original data
    expect(bytesToHex(result.stack[0]!)).toBe('ab');
    // Second item is the hash160 of 0xab (20 bytes)
    expect(result.stack[1]!.length).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// OP_IF / OP_ELSE / OP_ENDIF
// ---------------------------------------------------------------------------

describe('ScriptVM: OP_IF / OP_ELSE / OP_ENDIF', () => {
  it('takes true branch when OP_1 is on stack', () => {
    // OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    // 0x51 0x63 0x51 0x67 0x00 0x68
    const vm = new ScriptVM();
    const result = vm.executeHex('516351670068');
    expect(result.success).toBe(true);
    expect(decodeScriptNumber(result.stack[result.stack.length - 1]!)).toBe(1n);
  });

  it('takes false branch when OP_0 is on stack', () => {
    // OP_0 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF
    // 0x00 0x63 0x51 0x67 0x00 0x68
    const vm = new ScriptVM();
    const result = vm.executeHex('006351670068');
    expect(result.success).toBe(false); // OP_0 is falsy
    expect(decodeScriptNumber(result.stack[result.stack.length - 1]!)).toBe(0n);
  });
});

// ---------------------------------------------------------------------------
// OP_EQUAL
// ---------------------------------------------------------------------------

describe('ScriptVM: OP_EQUAL', () => {
  it('returns true for matching byte strings', () => {
    // Push 2 bytes "aabb", push 2 bytes "aabb", OP_EQUAL
    // 02aabb 02aabb 87
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb02aabb87');
    expect(result.success).toBe(true);
  });

  it('returns false for non-matching byte strings', () => {
    // Push 2 bytes "aabb", push 2 bytes "ccdd", OP_EQUAL
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb02ccdd87');
    expect(result.success).toBe(false);
  });

  it('returns true for matching numbers (OP_1 OP_1 OP_EQUAL)', () => {
    // OP_1 OP_1 OP_EQUAL: 51 51 87
    const vm = new ScriptVM();
    const result = vm.executeHex('515187');
    expect(result.success).toBe(true);
  });

  it('returns false for non-matching numbers (OP_1 OP_2 OP_EQUAL)', () => {
    const vm = new ScriptVM();
    const result = vm.executeHex('515287');
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// OP_VERIFY
// ---------------------------------------------------------------------------

describe('ScriptVM: OP_VERIFY', () => {
  it('succeeds on truthy value', () => {
    // OP_1 OP_VERIFY OP_1 (push something truthy back for overall success)
    // 0x51 0x69 0x51
    const vm = new ScriptVM();
    const result = vm.executeHex('516951');
    expect(result.success).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('fails on falsy value', () => {
    // OP_0 OP_VERIFY
    // 0x00 0x69
    const vm = new ScriptVM();
    const result = vm.executeHex('0069');
    expect(result.success).toBe(false);
    expect(result.error).toBe('OP_VERIFY failed');
  });
});

// ---------------------------------------------------------------------------
// OP_CAT (BSV re-enabled opcode)
// ---------------------------------------------------------------------------

describe('ScriptVM: OP_CAT', () => {
  it('concatenates two byte strings', () => {
    // Push "aa" (1 byte), push "bb" (1 byte), OP_CAT (0x7e)
    // 01aa 01bb 7e
    const vm = new ScriptVM();
    const result = vm.executeHex('01aa01bb7e');
    expect(result.stack.length).toBe(1);
    expect(bytesToHex(result.stack[0]!)).toBe('aabb');
  });

  it('concatenates multi-byte strings', () => {
    // Push "aabb" (2 bytes), push "ccdd" (2 bytes), OP_CAT
    // 02aabb 02ccdd 7e
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb02ccdd7e');
    expect(bytesToHex(result.stack[0]!)).toBe('aabbccdd');
  });

  it('concatenating with empty produces same value', () => {
    // Push "aabb", push empty (OP_0), OP_CAT
    // 02aabb 00 7e
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb007e');
    expect(bytesToHex(result.stack[0]!)).toBe('aabb');
  });
});

// ---------------------------------------------------------------------------
// OP_SPLIT (BSV re-enabled opcode)
// ---------------------------------------------------------------------------

describe('ScriptVM: OP_SPLIT', () => {
  it('splits a byte string at position 1', () => {
    // Push "aabbcc" (3 bytes), push 1 (OP_1), OP_SPLIT (0x7f)
    // 03aabbcc 51 7f
    const vm = new ScriptVM();
    const result = vm.executeHex('03aabbcc517f');
    expect(result.stack.length).toBe(2);
    expect(bytesToHex(result.stack[0]!)).toBe('aa');
    expect(bytesToHex(result.stack[1]!)).toBe('bbcc');
  });

  it('splits at position 0 yields empty left', () => {
    // Push "aabb", push OP_0, OP_SPLIT
    // 02aabb 00 7f
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb007f');
    expect(result.stack.length).toBe(2);
    expect(bytesToHex(result.stack[0]!)).toBe('');
    expect(bytesToHex(result.stack[1]!)).toBe('aabb');
  });

  it('splits at end yields empty right', () => {
    // Push "aabb" (2 bytes), push 2 (OP_2), OP_SPLIT
    // 02aabb 52 7f
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb527f');
    expect(result.stack.length).toBe(2);
    expect(bytesToHex(result.stack[0]!)).toBe('aabb');
    expect(bytesToHex(result.stack[1]!)).toBe('');
  });

  it('errors on out-of-range position', () => {
    // Push "aabb" (2 bytes), push 3 (OP_3), OP_SPLIT
    const vm = new ScriptVM();
    const result = vm.executeHex('02aabb537f');
    expect(result.success).toBe(false);
    expect(result.error).toContain('OP_SPLIT');
  });
});

// ---------------------------------------------------------------------------
// Stack overflow detection
// ---------------------------------------------------------------------------

describe('ScriptVM: stack overflow', () => {
  it('detects stack overflow when maxStackSize is exceeded', () => {
    const vm = new ScriptVM({ maxStackSize: 5 });
    // Push 6 items: OP_1 OP_1 OP_1 OP_1 OP_1 OP_1
    const result = vm.executeHex('515151515151');
    expect(result.success).toBe(false);
    expect(result.error).toContain('Stack size limit exceeded');
  });

  it('does not overflow when within limits', () => {
    const vm = new ScriptVM({ maxStackSize: 10 });
    // Push 5 items: OP_1 OP_1 OP_1 OP_1 OP_1
    const result = vm.executeHex('5151515151');
    expect(result.stack.length).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Max ops limit
// ---------------------------------------------------------------------------

describe('ScriptVM: max ops limit', () => {
  it('errors when operation limit is exceeded', () => {
    const vm = new ScriptVM({ maxOps: 3 });
    // OP_1 OP_DUP OP_DUP OP_DUP OP_DUP (4 non-push ops: 4 DUPs)
    // OP_1 is a push, not counted. OP_DUP = 0x76
    const result = vm.executeHex('5176767676');
    expect(result.success).toBe(false);
    expect(result.error).toContain('Operation limit exceeded');
  });

  it('succeeds when within ops limit', () => {
    const vm = new ScriptVM({ maxOps: 5 });
    // OP_1 OP_DUP OP_DUP (2 non-push ops)
    const result = vm.executeHex('517676');
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// executeScript and execute (unlocking + locking)
// ---------------------------------------------------------------------------

describe('ScriptVM: executeScript vs executeHex', () => {
  it('executeScript works with raw bytes', () => {
    const vm = new ScriptVM();
    const script = hexToBytes('515193'); // OP_1 OP_1 OP_ADD
    const result = vm.executeScript(script);
    expect(decodeScriptNumber(result.stack[result.stack.length - 1]!)).toBe(2n);
  });

  it('execute combines unlocking and locking scripts', () => {
    const vm = new ScriptVM();
    // Unlocking: push OP_1
    const unlocking = hexToBytes('51'); // OP_1
    // Locking: OP_1 OP_EQUAL
    const locking = hexToBytes('5187'); // OP_1 OP_EQUAL
    const result = vm.execute(unlocking, locking);
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Crypto operations
// ---------------------------------------------------------------------------

describe('ScriptVM: crypto operations', () => {
  it('OP_SHA256 produces 32-byte hash', () => {
    // Push 1 byte "ab", OP_SHA256 (0xa8)
    const vm = new ScriptVM();
    const result = vm.executeHex('01aba8');
    expect(result.stack.length).toBe(1);
    expect(result.stack[0]!.length).toBe(32);
  });

  it('OP_HASH160 produces 20-byte hash', () => {
    // Push 1 byte "ab", OP_HASH160 (0xa9)
    const vm = new ScriptVM();
    const result = vm.executeHex('01aba9');
    expect(result.stack.length).toBe(1);
    expect(result.stack[0]!.length).toBe(20);
  });

  it('OP_HASH256 produces 32-byte hash', () => {
    // Push 1 byte "ab", OP_HASH256 (0xaa)
    const vm = new ScriptVM();
    const result = vm.executeHex('01abaa');
    expect(result.stack.length).toBe(1);
    expect(result.stack[0]!.length).toBe(32);
  });
});
