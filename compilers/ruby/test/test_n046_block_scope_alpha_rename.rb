# frozen_string_literal: true

# N-046 (ScopeSnatcher) + N-047 (ShadowGoblin) — a block-scoped declaration,
# or a local of an inlined private helper, that reuses a name already bound in
# an enclosing scope gets its own ANF identity (user decision R24:
# alpha-rename, `<name>@<n>`). Port of
# packages/runar-compiler/src/__tests__/n046-block-scope-alpha-rename.test.ts.
#
# `let authorized = checkSig(sig, this.owner); if (trigger) { let authorized =
# true; } assert(authorized);` bound the inner `let` as `authorized`, the
# if-arm reconciliation took it for a reassignment of the outer local, and any
# signature unlocked the coins. An inlined output-emitting helper's local
# overwrote the caller's the same way.
#
# Oracle: alpha-equivalence, from the source language rather than compiler
# output. Renaming the inner declaration cannot change the program's meaning,
# so each template compiled with `$L` = the outer name must produce exactly the
# bytes of `$L` = `fresh`, in both constant-folding modes.
#
# Proves: in the Ruby tier, an inner `let` in a no-else if-arm, in both arms of
# an if/else, in a nested if (reassigned there), in a loop body, a loop
# variable reusing an outer local, an inner `let` reusing a parameter, and an
# inlined helper local reusing a caller local or parameter all compile like
# their renamed spellings. Does NOT prove: on-chain behaviour or cross-tier ANF
# naming (both in
# packages/runar-testing/src/__tests__/n046-block-scope-spend.test.ts).

require_relative "test_helper"

require "tmpdir"
require "runar_compiler/compiler"

class TestN046BlockScopeAlphaRename < Minitest::Test
  VAULT_HEAD = <<'SRC'

import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class ShadowVault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

SRC

  PAYOUT_HEAD = <<'SRC'

import { StatefulSmartContract, ByteString, PubKey, Sig, assert, checkSig, len } from 'runar-lang';

class OwnerPayout extends StatefulSmartContract {
  nonce: bigint;
  readonly owner: PubKey;

  constructor(nonce: bigint, owner: PubKey) {
    super(nonce, owner);
    this.nonce = nonce;
    this.owner = owner;
  }

SRC

  def self.vault(body)
    VAULT_HEAD + body + "}\n"
  end

  def self.payout(body)
    PAYOUT_HEAD + body + "}\n"
  end

  SHAPES = [
    ["ScopeSnatcher: inner let in a no-else if-arm", "authorized", vault(<<'SRC')],
  public spend(sig: Sig, trigger: boolean) {
    let authorized = checkSig(sig, this.owner);
    if (trigger) {
      let $L = true;
    }
    assert(authorized);
  }
SRC
    ["ScopeSnatcher: inner const in both arms of an if/else", "ok", vault(<<'SRC')],
  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      const $L = true;
      assert($L);
    } else {
      const $L = x < 0n;
      assert(!$L);
    }
    assert(ok);
  }
SRC
    ["inner let in a nested if, read and reassigned inside its scope", "ok", vault(<<'SRC')],
  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      if (x > 1n) {
        let $L = x > 5n;
        $L = !$L;
        assert($L || x == 7n);
      }
    }
    assert(ok);
  }
SRC
    ["inner let in a loop body", "ok", vault(<<'SRC')],
  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    for (let i = 0n; i < 2n; i++) {
      let $L = x > i;
      assert($L);
    }
    assert(ok);
  }
SRC
    ["loop variable reusing an outer local name", "i", vault(<<'SRC')],
  public spend(sig: Sig, x: bigint) {
    let i = x;
    let acc = 0n;
    for (let $L = 0n; $L < 3n; $L++) {
      acc = acc + $L;
    }
    assert(i == acc);
    assert(checkSig(sig, this.owner));
  }
SRC
    ["inner let reusing a parameter name", "x", vault(<<'SRC')],
  public spend(sig: Sig, x: bigint) {
    if (x > 0n) {
      let $L = 5n;
      assert($L == 5n);
    }
    assert(x == 7n);
    assert(checkSig(sig, this.owner));
  }
SRC
    ["ShadowGoblin: inlined helper local reusing a caller local name", "valid", payout(<<'SRC')],
  public withdraw(sig: Sig, destination: ByteString) {
    const valid = checkSig(sig, this.owner);
    this.pay(destination);
    assert(valid);
  }

  private pay(destination: ByteString) {
    const $L = len(destination) > 0n;
    assert($L);
    this.addRawOutput(50000n, destination);
  }
SRC
    ["inlined helper local reusing a caller parameter name", "sig", payout(<<'SRC')],
  public withdraw(sig: Sig, destination: ByteString) {
    this.pay(destination);
    assert(checkSig(sig, this.owner));
  }

  private pay(destination: ByteString) {
    const $L = len(destination);
    assert($L > 0n);
    this.addRawOutput(50000n, destination);
  }
SRC
  ].freeze

  def script_hex(source, disable_constant_folding)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "Shadow.runar.ts")
      File.write(path, source)
      RunarCompiler.compile_from_source(path, disable_constant_folding: disable_constant_folding).script
    end
  end

  def test_shadowing_declaration_compiles_like_renamed_spelling
    failures = []
    SHAPES.each do |name, outer, template|
      [true, false].each do |disable|
        begin
          shadow = script_hex(template.gsub("$L", outer), disable)
        rescue StandardError => e
          failures << "#{name} (disable_fold=#{disable}): shadowing spelling failed: #{e.message[0, 160]}"
          next
        end
        control = script_hex(template.gsub("$L", "fresh"), disable)
        failures << "#{name} (disable_fold=#{disable}): shadowing #{shadow} != renamed #{control}" if shadow != control
      end
    end
    assert_empty failures, failures.join("\n")
  end
end
