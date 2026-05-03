# frozen_string_literal: true

require_relative 'test_helper'

# Tests for the .runar.rs (Rust DSL) parser. Mirrors the Go suite at
# compilers/go/frontend/parser_rustmacro_test.go so all 7 compilers exercise
# the same surface shape on the same inputs.

class TestParserRs < Minitest::Test
  require 'runar_compiler/frontend/parser_rust'
  include RunarCompiler::Frontend

  def parse(source, file_name = 'Test.runar.rs')
    RunarCompiler.send(:_parse_source, source, file_name)
  end

  # ---------------------------------------------------------------------------
  # Basic Rust DSL P2PKH
  # ---------------------------------------------------------------------------

  def test_parses_p2pkh_contract
    source = <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct P2PKH {
          #[readonly]
          pub pub_key_hash: Addr,
      }

      #[runar::methods(P2PKH)]
      impl P2PKH {
          #[public]
          pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
              assert!(hash160(pub_key) == self.pub_key_hash);
              assert!(check_sig(sig, pub_key));
          }
      }
    RS

    result = parse(source, 'P2PKH.runar.rs')
    assert_empty result.errors.map(&:format_message),
                 'P2PKH should parse without errors'
    refute_nil result.contract

    c = result.contract
    assert_equal 'P2PKH', c.name
    assert_equal 'SmartContract', c.parent_class
    assert_equal 1, c.properties.length

    pkh = c.properties.first
    assert_equal 'pubKeyHash', pkh.name
    assert pkh.readonly, 'pub_key_hash should be readonly'

    assert_equal 1, c.methods.length
    unlock = c.methods.first
    assert_equal 'unlock', unlock.name
    assert_equal 'public', unlock.visibility
    # &self should be excluded; sig + pubKey remain.
    assert_equal 2, unlock.params.length
    assert_equal 'sig',    unlock.params[0].name
    assert_equal 'pubKey', unlock.params[1].name
  end

  # ---------------------------------------------------------------------------
  # Stateful Counter — non-readonly property selects StatefulSmartContract
  # ---------------------------------------------------------------------------

  def test_stateful_contract
    source = <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct Counter {
          pub count: Bigint,
      }

      #[runar::methods(Counter)]
      impl Counter {
          #[public]
          pub fn increment(&mut self) {
              self.count += 1;
          }

          #[public]
          pub fn decrement(&mut self) {
              assert!(self.count > 0);
              self.count -= 1;
          }
      }
    RS

    result = parse(source, 'Counter.runar.rs')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 'Counter', c.name
    assert_equal 'StatefulSmartContract', c.parent_class

    assert_equal 1, c.properties.length
    refute c.properties.first.readonly,
           'count should not be readonly in a stateful contract'

    assert_equal 2, c.methods.length
    assert_equal 'increment', c.methods[0].name
    assert_equal 'public',    c.methods[0].visibility
  end

  # ---------------------------------------------------------------------------
  # snake_case → camelCase for properties, methods, and params
  # ---------------------------------------------------------------------------

  def test_snake_to_camel_conversion
    source = <<~RS
      use runar::prelude::*;

      #[runar::contract]
      pub struct MyContract {
          #[readonly]
          pub pub_key_hash: Addr,
          pub my_balance: Bigint,
      }

      #[runar::methods(MyContract)]
      impl MyContract {
          #[public]
          pub fn verify_and_pay(&mut self, sig: &Sig, pub_key: &PubKey, fee_amount: Bigint) {
              assert!(check_sig(sig, pub_key));
              self.my_balance -= fee_amount;
          }

          fn compute_fee(&self, amount: Bigint) -> Bigint {
              percent_of(amount, 100)
          }
      }
    RS

    result = parse(source, 'MyContract.runar.rs')
    assert_empty result.errors.map(&:format_message)

    c = result.contract
    refute_nil c
    assert_equal 2, c.properties.length
    assert_equal 'pubKeyHash', c.properties[0].name
    assert_equal 'myBalance',  c.properties[1].name

    assert_equal 2, c.methods.length
    assert_equal 'verifyAndPay', c.methods[0].name
    assert_equal 'computeFee',   c.methods[1].name

    assert_equal 'public',  c.methods[0].visibility
    assert_equal 'private', c.methods[1].visibility

    pay = c.methods[0]
    assert_equal %w[sig pubKey feeAmount], pay.params.map(&:name)
  end

  # ---------------------------------------------------------------------------
  # Source without #[runar::contract] yields no real contract.
  #
  # The Ruby Rust parser, like the Go peer, accepts the input syntactically and
  # falls back to an empty/placeholder contract rather than synthesising a real
  # one. The invariant we assert is "no real properties or methods were
  # extracted", which is enough to catch a regression that started picking up
  # plain `fn` declarations as Rúnar methods.
  # ---------------------------------------------------------------------------

  def test_non_contract_source_yields_empty_contract
    source = <<~RS
      fn main() {
          println!("hello world");
      }
    RS

    result = parse(source, 'notacontract.runar.rs')

    # Either errors are reported, the contract is nil, or it is an empty
    # placeholder with no properties or non-constructor methods.
    if !result.errors.empty? || result.contract.nil?
      assert true
    else
      c = result.contract
      assert_empty c.properties,
                   'non-contract source should not produce real properties'
      non_ctor_methods = c.methods.reject { |m| m.name == 'constructor' }
      assert_empty non_ctor_methods,
                   'non-contract source should not produce real methods'
    end
  end
end
