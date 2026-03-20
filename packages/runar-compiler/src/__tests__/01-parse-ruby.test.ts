import { describe, it, expect } from 'vitest';
import { parseRubySource } from '../passes/01-parse-ruby.js';
import type {
  BinaryExpr,
  CallExpr,
  Identifier,
  BigIntLiteral,
  UnaryExpr,
  IfStatement,
  ForStatement,
  VariableDeclStatement,
  ExpressionStatement,
  ReturnStatement,
  AssignmentStatement,
  PropertyAccessExpr,
  TernaryExpr,
} from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helper contracts
// ---------------------------------------------------------------------------

const P2PKH_RB = `
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
`;

const COUNTER_RB = `
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
`;

const FUNGIBLE_TOKEN_RB = `
require 'runar'

class FungibleToken < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :token_id, ByteString, readonly: true

  def initialize(owner, balance, token_id)
    super(owner, balance, token_id)
    @owner = owner
    @balance = balance
    @token_id = token_id
  end

  runar_public sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint
  def transfer(sig, to, amount, output_satoshis)
    assert check_sig(sig, @owner)
    assert amount > 0
    assert amount <= @balance
    add_output(output_satoshis, to, amount)
    add_output(output_satoshis, @owner, @balance - amount)
  end

  runar_public sig: Sig, to: PubKey, output_satoshis: Bigint
  def send_all(sig, to, output_satoshis)
    assert check_sig(sig, @owner)
    add_output(output_satoshis, to, @balance)
  end
end
`;

const ESCROW_RB = `
require 'runar'

class Escrow < Runar::SmartContract
  prop :buyer, PubKey
  prop :seller, PubKey
  prop :arbiter, PubKey

  def initialize(buyer, seller, arbiter)
    super(buyer, seller, arbiter)
    @buyer = buyer
    @seller = seller
    @arbiter = arbiter
  end

  runar_public sig: Sig
  def release_by_seller(sig)
    assert check_sig(sig, @seller)
  end

  runar_public sig: Sig
  def release_by_arbiter(sig)
    assert check_sig(sig, @arbiter)
  end

  runar_public sig: Sig
  def refund_to_buyer(sig)
    assert check_sig(sig, @buyer)
  end
end
`;

// ---------------------------------------------------------------------------
// Contract structure
// ---------------------------------------------------------------------------

describe('Ruby Parser', () => {
  describe('contract structure', () => {
    it('parses a P2PKH contract and returns a ContractNode', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract).not.toBeNull();
      expect(result.contract!.kind).toBe('contract');
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('sets parentClass to SmartContract', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('sets parentClass to StatefulSmartContract', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      expect(result.contract!.parentClass).toBe('StatefulSmartContract');
    });

    it('uses default fileName when none provided', () => {
      const result = parseRubySource(P2PKH_RB);
      expect(result.contract!.sourceFile).toBe('contract.runar.rb');
    });

    it('uses custom fileName when provided', () => {
      const result = parseRubySource(P2PKH_RB, 'p2pkh.runar.rb');
      expect(result.contract!.sourceFile).toBe('p2pkh.runar.rb');
    });

    it('skips require statement', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      expect(result.contract!.name).toBe('P2PKH');
    });

    it('handles Runar:: namespace prefix on parent class', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      expect(result.contract!.parentClass).toBe('SmartContract');
    });

    it('handles bare parent class without Runar:: prefix', () => {
      const rb = `
class Foo < SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      expect(result.contract!.parentClass).toBe('SmartContract');
    });
  });

  // ---------------------------------------------------------------------------
  // Properties
  // ---------------------------------------------------------------------------

  describe('properties', () => {
    it('extracts properties from prop declarations', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.contract!.properties).toHaveLength(1);
      expect(result.contract!.properties[0]!.name).toBe('pubKeyHash');
      expect(result.contract!.properties[0]!.type).toEqual({ kind: 'primitive_type', name: 'Addr' });
    });

    it('marks all SmartContract properties as readonly', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.contract!.properties[0]!.readonly).toBe(true);
    });

    it('marks StatefulSmartContract properties as mutable by default', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      expect(result.contract!.properties[0]!.name).toBe('count');
      expect(result.contract!.properties[0]!.readonly).toBe(false);
    });

    it('supports readonly: true in StatefulSmartContract', () => {
      const result = parseRubySource(FUNGIBLE_TOKEN_RB, 'FT.runar.rb');
      const tokenId = result.contract!.properties.find(p => p.name === 'tokenId');
      expect(tokenId).toBeDefined();
      expect(tokenId!.readonly).toBe(true);
    });

    it('parses multiple properties', () => {
      const result = parseRubySource(ESCROW_RB, 'Escrow.runar.rb');
      expect(result.contract!.properties).toHaveLength(3);
      expect(result.contract!.properties.map(p => p.name)).toEqual(['buyer', 'seller', 'arbiter']);
    });

    it('converts snake_case property names to camelCase', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.contract!.properties[0]!.name).toBe('pubKeyHash');
    });

    it('maps Bigint type to bigint primitive', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      expect(result.contract!.properties[0]!.type).toEqual({ kind: 'primitive_type', name: 'bigint' });
    });
  });

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('parses initialize as constructor', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.contract!.constructor.name).toBe('constructor');
      expect(result.contract!.constructor.visibility).toBe('public');
    });

    it('parses constructor parameters', () => {
      const result = parseRubySource(FUNGIBLE_TOKEN_RB, 'FT.runar.rb');
      expect(result.contract!.constructor.params).toHaveLength(3);
    });

    it('parses super call in constructor body', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const body = result.contract!.constructor.body;
      expect(body.length).toBeGreaterThan(0);
      const superStmt = body[0]! as ExpressionStatement;
      expect(superStmt.kind).toBe('expression_statement');
      const callExpr = superStmt.expression as CallExpr;
      expect(callExpr.kind).toBe('call_expr');
      expect((callExpr.callee as Identifier).name).toBe('super');
    });

    it('parses instance variable assignments in constructor', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const body = result.contract!.constructor.body;
      // super call + @pub_key_hash = pub_key_hash
      expect(body.length).toBe(2);
      const assign = body[1]! as AssignmentStatement;
      expect(assign.kind).toBe('assignment');
      expect((assign.target as PropertyAccessExpr).property).toBe('pubKeyHash');
    });

    it('auto-generates constructor when none provided', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint

  runar_public
  def bar
    assert @x > 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      expect(result.contract!.constructor.name).toBe('constructor');
      expect(result.contract!.constructor.params).toHaveLength(1);
      expect(result.contract!.constructor.params[0]!.name).toBe('x');
    });
  });

  // ---------------------------------------------------------------------------
  // Methods and visibility
  // ---------------------------------------------------------------------------

  describe('methods', () => {
    it('parses public methods marked with runar_public', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      const inc = result.contract!.methods.find(m => m.name === 'increment');
      expect(inc).toBeDefined();
      expect(inc!.visibility).toBe('public');
    });

    it('defaults methods to private without runar_public', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint

  def initialize(x)
    super(x)
    @x = x
  end

  def helper
    return @x
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const helper = result.contract!.methods.find(m => m.name === 'helper');
      expect(helper).toBeDefined();
      expect(helper!.visibility).toBe('private');
    });

    it('parses parameter types from runar_public', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const unlock = result.contract!.methods.find(m => m.name === 'unlock');
      expect(unlock).toBeDefined();
      expect(unlock!.params).toHaveLength(2);
      expect(unlock!.params[0]!.name).toBe('sig');
      expect(unlock!.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });
      expect(unlock!.params[1]!.name).toBe('pubKey');
      expect(unlock!.params[1]!.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });
    });

    it('parses no-arg public methods', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      const inc = result.contract!.methods.find(m => m.name === 'increment');
      expect(inc).toBeDefined();
      expect(inc!.params).toHaveLength(0);
    });

    it('converts snake_case method names to camelCase', () => {
      const result = parseRubySource(ESCROW_RB, 'Escrow.runar.rb');
      const method = result.contract!.methods.find(m => m.name === 'releaseBySeller');
      expect(method).toBeDefined();
    });

    it('parses multi-method contracts', () => {
      const result = parseRubySource(ESCROW_RB, 'Escrow.runar.rb');
      expect(result.contract!.methods).toHaveLength(3);
    });

    it('converts snake_case parameter names to camelCase', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const unlock = result.contract!.methods.find(m => m.name === 'unlock');
      expect(unlock!.params[1]!.name).toBe('pubKey');
    });
  });

  // ---------------------------------------------------------------------------
  // Expressions and operators
  // ---------------------------------------------------------------------------

  describe('expressions', () => {
    it('maps == to === in AST', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const unlock = result.contract!.methods.find(m => m.name === 'unlock')!;
      // First statement is assert hash160(pub_key) == @pub_key_hash
      const assertStmt = unlock.body[0] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const eqExpr = assertCall.args[0] as BinaryExpr;
      expect(eqExpr.op).toBe('===');
    });

    it('maps != to !== in AST', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x != 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const neqExpr = assertCall.args[0] as BinaryExpr;
      expect(neqExpr.op).toBe('!==');
    });

    it('maps and/or to &&/|| in AST', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x > 0 and @x < 10
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const andExpr = assertCall.args[0] as BinaryExpr;
      expect(andExpr.op).toBe('&&');
    });

    it('maps not to ! in AST', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert not @x == 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const notExpr = assertCall.args[0] as UnaryExpr;
      expect(notExpr.op).toBe('!');
    });

    it('maps ** to pow() call', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x ** 2 > 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const cmpExpr = assertCall.args[0] as BinaryExpr;
      const powCall = cmpExpr.left as CallExpr;
      expect(powCall.kind).toBe('call_expr');
      expect((powCall.callee as Identifier).name).toBe('pow');
      expect(powCall.args).toHaveLength(2);
    });

    it('parses instance variable access as PropertyAccessExpr', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      const dec = result.contract!.methods.find(m => m.name === 'decrement')!;
      // assert @count > 0
      const assertStmt = dec.body[0] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const cmpExpr = assertCall.args[0] as BinaryExpr;
      expect(cmpExpr.left).toEqual({ kind: 'property_access', property: 'count' });
    });

    it('parses ternary expressions', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    y = @x > 0 ? @x : 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const varDecl = bar.body[0] as VariableDeclStatement;
      const ternary = varDecl.init as TernaryExpr;
      expect(ternary.kind).toBe('ternary_expr');
    });

    it('converts snake_case builtin names to camelCase', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const unlock = result.contract!.methods.find(m => m.name === 'unlock')!;
      // Second assert: check_sig(sig, pub_key) -> checkSig
      const assertStmt = unlock.body[1] as ExpressionStatement;
      const assertCall = assertStmt.expression as CallExpr;
      const innerCall = assertCall.args[0] as CallExpr;
      expect((innerCall.callee as Identifier).name).toBe('checkSig');
    });
  });

  // ---------------------------------------------------------------------------
  // Statements
  // ---------------------------------------------------------------------------

  describe('statements', () => {
    it('parses assert as function call', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      const dec = result.contract!.methods.find(m => m.name === 'decrement')!;
      const assertStmt = dec.body[0] as ExpressionStatement;
      expect(assertStmt.kind).toBe('expression_statement');
      const call = assertStmt.expression as CallExpr;
      expect(call.kind).toBe('call_expr');
      expect((call.callee as Identifier).name).toBe('assert');
    });

    it('parses compound assignment @count += 1', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      const inc = result.contract!.methods.find(m => m.name === 'increment')!;
      const assign = inc.body[0] as AssignmentStatement;
      expect(assign.kind).toBe('assignment');
      expect((assign.target as PropertyAccessExpr).property).toBe('count');
      const binExpr = assign.value as BinaryExpr;
      expect(binExpr.op).toBe('+');
      expect((binExpr.right as BigIntLiteral).value).toBe(1n);
    });

    it('parses compound assignment @count -= 1', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      const dec = result.contract!.methods.find(m => m.name === 'decrement')!;
      const assign = dec.body[1] as AssignmentStatement;
      expect(assign.kind).toBe('assignment');
      const binExpr = assign.value as BinaryExpr;
      expect(binExpr.op).toBe('-');
    });

    it('parses add_output as addOutput function call', () => {
      const result = parseRubySource(FUNGIBLE_TOKEN_RB, 'FT.runar.rb');
      const transfer = result.contract!.methods.find(m => m.name === 'transfer')!;
      // After 3 assert statements, there should be add_output calls
      const addOutputStmt = transfer.body[3] as ExpressionStatement;
      expect(addOutputStmt.kind).toBe('expression_statement');
      const call = addOutputStmt.expression as CallExpr;
      expect(call.kind).toBe('call_expr');
      expect((call.callee as Identifier).name).toBe('addOutput');
    });

    it('parses variable declarations', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    y = @x + 1
    assert y > 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const varDecl = bar.body[0] as VariableDeclStatement;
      expect(varDecl.kind).toBe('variable_decl');
      expect(varDecl.name).toBe('y');
      expect(varDecl.mutable).toBe(true);
    });

    it('parses return statements', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  def helper
    return @x + 1
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const ret = helper.body[0] as ReturnStatement;
      expect(ret.kind).toBe('return_statement');
      expect(ret.value).toBeDefined();
    });

    it('parses return statement without value', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  def helper
    return
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const ret = helper.body[0] as ReturnStatement;
      expect(ret.kind).toBe('return_statement');
      expect(ret.value).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Control flow
  // ---------------------------------------------------------------------------

  describe('control flow', () => {
    it('parses if/end', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    if @x > 0
      @x = @x + 1
    end
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const ifStmt = bar.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then).toHaveLength(1);
      expect(ifStmt.else).toBeUndefined();
    });

    it('parses if/else/end', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    if @x > 0
      @x = @x + 1
    else
      @x = 0
    end
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const ifStmt = bar.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then).toHaveLength(1);
      expect(ifStmt.else).toHaveLength(1);
    });

    it('parses if/elsif/else/end', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    if @x > 10
      @x = 10
    elsif @x > 0
      @x = @x + 1
    else
      @x = 0
    end
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const ifStmt = bar.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      expect(ifStmt.then).toHaveLength(1);
      // else branch contains an elsif which is a nested if_statement
      expect(ifStmt.else).toHaveLength(1);
      const nestedIf = ifStmt.else![0] as IfStatement;
      expect(nestedIf.kind).toBe('if_statement');
      expect(nestedIf.else).toHaveLength(1);
    });

    it('parses unless as negated if', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    unless @x == 0
      @x = @x - 1
    end
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const ifStmt = bar.body[0] as IfStatement;
      expect(ifStmt.kind).toBe('if_statement');
      // Condition should be negated
      const cond = ifStmt.condition as UnaryExpr;
      expect(cond.op).toBe('!');
    });

    it('parses for loop with exclusive range (...)', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    for i in 0...@x
      assert i >= 0
    end
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const forStmt = bar.body[0] as ForStatement;
      expect(forStmt.kind).toBe('for_statement');
      expect(forStmt.init.name).toBe('i');
      // Exclusive range: condition is i < @x
      const cond = forStmt.condition as BinaryExpr;
      expect(cond.op).toBe('<');
    });

    it('parses for loop with inclusive range (..)', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    for i in 0..@x
      assert i >= 0
    end
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const forStmt = bar.body[0] as ForStatement;
      const cond = forStmt.condition as BinaryExpr;
      // Inclusive range: condition is i <= @x
      expect(cond.op).toBe('<=');
    });
  });

  // ---------------------------------------------------------------------------
  // snake_case to camelCase conversion
  // ---------------------------------------------------------------------------

  describe('snake_case to camelCase', () => {
    it('converts multi-word property names', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      expect(result.contract!.properties[0]!.name).toBe('pubKeyHash');
    });

    it('converts method names', () => {
      const result = parseRubySource(ESCROW_RB, 'Escrow.runar.rb');
      expect(result.contract!.methods.map(m => m.name)).toContain('releaseBySeller');
      expect(result.contract!.methods.map(m => m.name)).toContain('releaseByArbiter');
      expect(result.contract!.methods.map(m => m.name)).toContain('refundToBuyer');
    });

    it('converts parameter names', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const unlock = result.contract!.methods.find(m => m.name === 'unlock')!;
      expect(unlock.params.map(p => p.name)).toContain('pubKey');
    });

    it('preserves single-word names', () => {
      const result = parseRubySource(COUNTER_RB, 'Counter.runar.rb');
      expect(result.contract!.properties[0]!.name).toBe('count');
    });

    it('converts instance variable references in expressions', () => {
      const result = parseRubySource(P2PKH_RB, 'P2PKH.runar.rb');
      const unlock = result.contract!.methods.find(m => m.name === 'unlock')!;
      const assertStmt = unlock.body[0] as ExpressionStatement;
      const call = assertStmt.expression as CallExpr;
      const eqExpr = call.args[0] as BinaryExpr;
      expect((eqExpr.right as PropertyAccessExpr).property).toBe('pubKeyHash');
    });
  });

  // ---------------------------------------------------------------------------
  // Stateful contracts with multi-output
  // ---------------------------------------------------------------------------

  describe('stateful contracts', () => {
    it('parses fungible token with readonly and mutable properties', () => {
      const result = parseRubySource(FUNGIBLE_TOKEN_RB, 'FT.runar.rb');
      expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
      const props = result.contract!.properties;
      expect(props).toHaveLength(3);

      const owner = props.find(p => p.name === 'owner')!;
      expect(owner.readonly).toBe(false);
      expect(owner.type).toEqual({ kind: 'primitive_type', name: 'PubKey' });

      const balance = props.find(p => p.name === 'balance')!;
      expect(balance.readonly).toBe(false);
      expect(balance.type).toEqual({ kind: 'primitive_type', name: 'bigint' });

      const tokenId = props.find(p => p.name === 'tokenId')!;
      expect(tokenId.readonly).toBe(true);
      expect(tokenId.type).toEqual({ kind: 'primitive_type', name: 'ByteString' });
    });

    it('parses multiple methods with different param types', () => {
      const result = parseRubySource(FUNGIBLE_TOKEN_RB, 'FT.runar.rb');
      const methods = result.contract!.methods;
      expect(methods).toHaveLength(2);

      const transfer = methods.find(m => m.name === 'transfer')!;
      expect(transfer.params).toHaveLength(4);
      expect(transfer.params[0]!.type).toEqual({ kind: 'primitive_type', name: 'Sig' });

      const sendAll = methods.find(m => m.name === 'sendAll')!;
      expect(sendAll.params).toHaveLength(3);
    });

    it('parses add_output calls with correct argument count', () => {
      const result = parseRubySource(FUNGIBLE_TOKEN_RB, 'FT.runar.rb');
      const transfer = result.contract!.methods.find(m => m.name === 'transfer')!;
      // Body: 3 asserts + 2 add_output calls
      expect(transfer.body).toHaveLength(5);
      const addOutput1 = transfer.body[3] as ExpressionStatement;
      const call1 = addOutput1.expression as CallExpr;
      expect((call1.callee as Identifier).name).toBe('addOutput');
      expect(call1.args).toHaveLength(3);
    });
  });

  // ---------------------------------------------------------------------------
  // Numeric and literal parsing
  // ---------------------------------------------------------------------------

  describe('literals', () => {
    it('parses integer literals', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x == 42
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const call = assertStmt.expression as CallExpr;
      const eq = call.args[0] as BinaryExpr;
      expect((eq.right as BigIntLiteral).value).toBe(42n);
    });

    it('parses hex integer literals', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x == 0xFF
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const call = assertStmt.expression as CallExpr;
      const eq = call.args[0] as BinaryExpr;
      expect((eq.right as BigIntLiteral).value).toBe(255n);
    });

    it('parses boolean literals', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert true
    assert not false
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const stmt1 = bar.body[0] as ExpressionStatement;
      const call1 = stmt1.expression as CallExpr;
      expect(call1.args[0]).toEqual({ kind: 'bool_literal', value: true });
    });

    it('parses hex bytestring literals (single-quoted)', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, ByteString
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x == 'deadbeef'
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const assertStmt = bar.body[0] as ExpressionStatement;
      const call = assertStmt.expression as CallExpr;
      const eq = call.args[0] as BinaryExpr;
      expect(eq.right).toEqual({ kind: 'bytestring_literal', value: 'deadbeef' });
    });
  });

  // ---------------------------------------------------------------------------
  // Array literals
  // ---------------------------------------------------------------------------

  describe('array literals', () => {
    it('parses a multi-element array literal as array_literal node', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar(a, b, c)
    arr = [a, b, c]
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const decl = bar.body[0] as VariableDeclStatement;
      const init = decl.init as { kind: string; elements: unknown[] };
      expect(init.kind).toBe('array_literal');
      expect(init.elements).toHaveLength(3);
    });

    it('parses an empty array literal', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    arr = []
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const decl = bar.body[0] as VariableDeclStatement;
      const init = decl.init as { kind: string; elements: unknown[] };
      expect(init.kind).toBe('array_literal');
      expect(init.elements).toHaveLength(0);
    });

    it('parses a single-element array literal', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar(a)
    arr = [a]
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const bar = result.contract!.methods.find(m => m.name === 'bar')!;
      const decl = bar.body[0] as VariableDeclStatement;
      const init = decl.init as { kind: string; elements: unknown[] };
      expect(init.kind).toBe('array_literal');
      expect(init.elements).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------------------
  // B2: leading underscore name conversion
  // ---------------------------------------------------------------------------

  describe('leading underscore name conversion', () => {
    const PRIVATE_METHODS_RB = `
require 'runar'

class Foo < Runar::StatefulSmartContract
  prop :balance, Bigint

  def initialize(balance)
    super(balance)
    @balance = balance
  end

  runar_public sig: Sig
  def deposit(sig)
    _require_owner(sig)
    @balance += 1
  end

  private

  params sig: Sig
  def _require_owner(sig)
    assert check_sig(sig, @balance)
  end
end
`;

    it('strips leading underscore from private method names', () => {
      const result = parseRubySource(PRIVATE_METHODS_RB, 'Foo.runar.rb');
      const priv = result.contract!.methods.find(m => m.visibility === 'private');
      expect(priv).toBeDefined();
      expect(priv!.name).toBe('requireOwner');
    });

    it('strips leading underscore from method call sites', () => {
      const result = parseRubySource(PRIVATE_METHODS_RB, 'Foo.runar.rb');
      const deposit = result.contract!.methods.find(m => m.name === 'deposit')!;
      const callStmt = deposit.body[0] as ExpressionStatement;
      const call = callStmt.expression as CallExpr;
      // Bare method calls are rewritten to this.methodName() (property_access)
      expect((call.callee as PropertyAccessExpr).property).toBe('requireOwner');
    });

    it('converts _snake_case to camelCase without leading capital', () => {
      const rb = `
class Foo < Runar::StatefulSmartContract
  prop :val, Bigint
  def initialize(val)
    super(val)
    @val = val
  end
  runar_public
  def go
    @val = _compute_fee_amount(1)
  end
  private
  params x: Bigint
  def _compute_fee_amount(x)
    x + 1
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const priv = result.contract!.methods.find(m => m.visibility === 'private');
      expect(priv!.name).toBe('computeFeeAmount');
    });
  });

  // ---------------------------------------------------------------------------
  // B1: implicit returns in private methods
  // ---------------------------------------------------------------------------

  describe('implicit returns in private methods', () => {
    it('converts last expression to return statement', () => {
      const rb = `
class Foo < Runar::StatefulSmartContract
  prop :val, Bigint
  def initialize(val)
    super(val)
    @val = val
  end
  runar_public
  def go
    @val = _helper(1)
  end
  private
  params x: Bigint
  def _helper(x)
    x + 1
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const helper = result.contract!.methods.find(m => m.name === 'helper')!;
      const last = helper.body[helper.body.length - 1] as ReturnStatement;
      expect(last.kind).toBe('return_statement');
      expect(last.value).toBeDefined();
    });

    it('converts assert expression statements to returns in private methods', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def go
    _check(@x)
  end
  private
  params v: Bigint
  def _check(v)
    assert v > 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const check = result.contract!.methods.find(m => m.name === 'check')!;
      const last = check.body[check.body.length - 1]!;
      // assert is an expression_statement wrapping a call — it should be converted
      // to a return since it's the last expression in a private method
      expect(last.kind).toBe('return_statement');
    });

    it('does not affect public methods', () => {
      const rb = `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def go
    assert @x > 0
  end
end
`;
      const result = parseRubySource(rb, 'Foo.runar.rb');
      const go = result.contract!.methods.find(m => m.name === 'go')!;
      const last = go.body[go.body.length - 1]!;
      expect(last.kind).toBe('expression_statement');
    });
  });

  // ---------------------------------------------------------------------------
  // Integration: full parse via dispatcher
  // ---------------------------------------------------------------------------

  describe('integration', () => {
    it('parses without errors for all example contracts', () => {
      for (const [name, src] of [
        ['P2PKH', P2PKH_RB],
        ['Counter', COUNTER_RB],
        ['FungibleToken', FUNGIBLE_TOKEN_RB],
        ['Escrow', ESCROW_RB],
      ] as const) {
        const result = parseRubySource(src, `${name}.runar.rb`);
        const errors = result.errors.filter(e => e.severity === 'error');
        expect(errors).toEqual([]);
        expect(result.contract).not.toBeNull();
      }
    });
  });
});
