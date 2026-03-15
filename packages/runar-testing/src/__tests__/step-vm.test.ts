import { describe, it, expect } from 'vitest';
import { ScriptVM, hexToBytes, bytesToHex } from '../vm/index.js';

describe('ScriptVM step mode', () => {
  it('steps through a simple script and reports each opcode', () => {
    const vm = new ScriptVM();
    // Script: OP_1 OP_2 OP_ADD → stack should be [3]
    vm.loadHex('', '515293');

    const steps = [];
    while (!vm.isComplete) {
      const result = vm.step();
      if (result) steps.push(result);
    }

    expect(steps.length).toBe(3);
    expect(steps[0]!.opcode).toBe('OP_1');
    expect(steps[1]!.opcode).toBe('OP_2');
    expect(steps[2]!.opcode).toBe('OP_ADD');

    // Final stack should have [3]
    expect(vm.isSuccess).toBe(true);
    expect(vm.currentStack.length).toBe(1);
  });

  it('handles push data opcodes', () => {
    const vm = new ScriptVM();
    // Push 3 bytes: 0x03 0xaa 0xbb 0xcc
    vm.loadHex('', '03aabbcc');

    const step = vm.step();
    expect(step).not.toBeNull();
    expect(step!.opcode).toBe('PUSH_3');
    expect(bytesToHex(step!.mainStack[0]!)).toBe('aabbcc');
  });

  it('reports errors correctly', () => {
    const vm = new ScriptVM();
    // OP_1 OP_VERIFY OP_0 OP_VERIFY → second verify should fail
    vm.loadHex('', '51690069');

    const step1 = vm.step(); // OP_1
    expect(step1!.error).toBeUndefined();

    const step2 = vm.step(); // OP_VERIFY (succeeds, stack [1] -> [])
    expect(step2!.error).toBeUndefined();

    const step3 = vm.step(); // OP_0
    expect(step3!.error).toBeUndefined();

    const step4 = vm.step(); // OP_VERIFY (fails, stack [0])
    expect(step4!.error).toBeDefined();
    expect(vm.isComplete).toBe(true);
    expect(vm.isSuccess).toBe(false);
  });

  it('handles unlocking + locking scripts', () => {
    const vm = new ScriptVM();
    // Unlocking: OP_1   Locking: OP_1 OP_EQUAL
    vm.loadHex('51', '5187');

    const step1 = vm.step();
    expect(step1!.context).toBe('unlocking');
    expect(step1!.opcode).toBe('OP_1');

    const step2 = vm.step();
    expect(step2!.context).toBe('locking');
    expect(step2!.opcode).toBe('OP_1');

    const step3 = vm.step();
    expect(step3!.context).toBe('locking');
    expect(step3!.opcode).toBe('OP_EQUAL');

    // One more step to trigger end-of-script completion
    const step4 = vm.step();
    expect(step4).toBeNull(); // No more opcodes

    expect(vm.isComplete).toBe(true);
    expect(vm.isSuccess).toBe(true);
  });

  it('handles if/else/endif correctly', () => {
    const vm = new ScriptVM();
    // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    vm.loadHex('', '516352675468');

    const steps = [];
    while (!vm.isComplete) {
      const result = vm.step();
      if (result) steps.push(result);
    }

    // Should execute: OP_1, OP_IF, OP_2, OP_ENDIF
    // (OP_ELSE and OP_3 are in the non-executing branch)
    expect(vm.isSuccess).toBe(true);
    // Stack should have [2] (from the then branch)
    expect(vm.currentStack.length).toBe(1);
  });

  it('step returns null after completion', () => {
    const vm = new ScriptVM();
    vm.loadHex('', '51'); // OP_1

    vm.step(); // Execute OP_1
    vm.step(); // End of script → returns null, sets isComplete

    expect(vm.isComplete).toBe(true);
    expect(vm.step()).toBeNull(); // Already complete
  });

  it('produces same result as execute()', () => {
    const vm1 = new ScriptVM();
    const vm2 = new ScriptVM();

    // A more complex script: OP_5 OP_3 OP_SUB OP_2 OP_EQUAL
    const locking = hexToBytes('555394529c');

    // Full execution
    const result = vm1.executeScript(locking);

    // Step execution
    vm2.loadHex('', '555394529c');
    while (!vm2.isComplete) vm2.step();

    expect(vm2.isSuccess).toBe(result.success);
    expect(vm2.currentStack.length).toBe(result.stack.length);
  });
});
