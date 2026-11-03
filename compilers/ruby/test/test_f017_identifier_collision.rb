# frozen_string_literal: true

# F-017 — two distinct source identifiers that a surface's name conversion maps
# to ONE Rúnar name are refused with one shared diagnostic.
#
# Before the rule, `tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)` in a
# .runar.py contract (always false under Python semantics) bound both
# spellings to one variable and compiled to `OP_DUP OP_DUP OP_NUMEQUAL`: an
# always-TRUE guard.
#
# This tier ALSO mapped differently from the reference: `String#split("_")`
# drops trailing empty fields, so `tmp_` stayed `tmp_` on .runar.rs and
# `tmp__` stayed `tmp_` on .runar.py where every other tier says `tmp`. The
# `rs-param` and `py-tmp__` cases pin the converged mapping.
#
# What this proves: the Ruby tier's frontend refuses a collision on each of the
# five renaming surfaces (.py/.rs/.rb/.move/.go) with exactly the text the TS
# reference emits, picks the same pair regardless of declaration order, and
# does not refuse `sum_` on its own or a local that reuses a property's exact
# spelling.
# What it does NOT prove: anything about the other tiers (their own suites and
# conformance/negatives/N46-N50 cover that), or the semantics of a local that
# shadows a property under the same spelling (N-016, a separate item).
#
# The compiler is invoked via subprocess (`--parse-only`) for the same reason
# as test_conformance_goldens.rb: the parsers share a constant namespace, so
# running several of them in-process corrupts tokenization.

require 'open3'
require 'tmpdir'
require_relative 'test_helper'

class F017IdentifierCollisionTest < Minitest::Test
  RUBY_CLI = File.expand_path('../bin/runar-compiler-ruby', __dir__)

  def msg(a, b, name)
    "identifier collision: '#{a}' and '#{b}' both convert to '#{name}'; rename one of them"
  end

  def py(body)
    "from runar import SmartContract, Bigint, public, assert_\n\n\n" \
      "class Trail(SmartContract):\n    k: Bigint\n\n" \
      "    def __init__(self, k: Bigint):\n        super().__init__(k)\n        self.k = k\n\n" \
      "    @public\n    def unlock(self, n: Bigint):\n#{body}\n"
  end

  RS = <<~RS
    use runar::prelude::*;

    #[runar::contract]
    struct Trail {
        #[readonly]
        k: Int,
    }

    impl Trail {
        pub fn unlock(&self, n: Int) {
            let n_ = n + 1;
            assert!(n_ == n);
        }
    }
  RS

  RB = <<~RB
    require 'runar'

    class Trail < Runar::SmartContract
      prop :k, Bigint

      def initialize(k)
        super(k)
        @k = k
      end

      runar_public n: Bigint
      def unlock(n)
        k_ = n + 1
        assert k_ == @k
      end
    end
  RB

  MOVE = <<~MOVE
    module Trail {
        use runar::types::{Int};

        struct Trail {
            k: Int,
        }

        public fun unlock(contract: &Trail, n: Int) {
            let tmp = n + 1;
            let tmp_ = n + 2;
            assert!(tmp == tmp_, 0);
        }
    }
  MOVE

  GO = "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\n" \
       "type Trail struct {\n\trunar.SmartContract\n\tK runar.Int `runar:\"readonly\"`\n}\n\n" \
       "func (c *Trail) Unlock(n runar.Int) {\n\tk := n + 1\n\trunar.Assert(k == c.K)\n}\n"

  # [exit status, the identifier-collision lines of the diagnostic]
  def parse_only(source, file_name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, source)
      stdout, stderr, status = Open3.capture3(RbConfig.ruby, RUBY_CLI, '--source', path, '--parse-only')
      found = "#{stderr}\n#{stdout}".scan(/identifier collision: [^\n]*rename one of them/)
      [status.exitstatus, found]
    end
  end

  def assert_refused(source, file_name, expected)
    status, found = parse_only(source, file_name)
    refute_equal 0, status, "#{file_name} was accepted; it must be refused"
    assert_equal [expected], found
  end

  def test_py_collisions_refused
    assert_refused(py("        tmp = n + 1\n        tmp_ = n + 2\n        assert_(tmp == tmp_)"), 'Trail.runar.py', msg('tmp', 'tmp_', 'tmp'))
    assert_refused(py("        tmp = n + 1\n        tmp__ = n + 2\n        assert_(tmp == tmp__)"), 'Trail.runar.py', msg('tmp', 'tmp__', 'tmp'))
    assert_refused(py("        _tmp = n + 1\n        tmp = n + 2\n        assert_(_tmp == tmp)"), 'Trail.runar.py', msg('_tmp', 'tmp', 'tmp'))
    assert_refused(py("        a__b = n + 1\n        a_b = n + 2\n        assert_(a__b == a_b)"), 'Trail.runar.py', msg('a__b', 'a_b', 'aB'))
    assert_refused(py("        acc = n\n        for i_ in range(3):\n            acc = acc + 1\n        i = acc\n        assert_(i == n + 3)"), 'Trail.runar.py', msg('i', 'i_', 'i'))
  end

  def test_rs_rb_move_go_collisions_refused
    assert_refused(RS, 'Trail.runar.rs', msg('n', 'n_', 'n'))
    assert_refused(RB, 'Trail.runar.rb', msg('k', 'k_', 'k'))
    assert_refused(MOVE, 'Trail.runar.move', msg('tmp', 'tmp_', 'tmp'))
    assert_refused(GO, 'Trail.runar.go', msg('K', 'k', 'k'))
  end

  def test_pair_choice_is_independent_of_declaration_order
    assert_refused(
      py("        z_ = n + 1\n        z = n + 2\n        b__c = n + 3\n        b_c = n + 4\n        bC = n + 5\n        assert_(z + z_ + b__c + b_c + bC > 0)"),
      'Trail.runar.py', msg('bC', 'b__c', 'bC')
    )
  end

  def test_non_colliding_names_accepted
    [
      "        x = n + 1\n        y = n + 2\n        assert_(x != y)",
      "        sum_ = n + 1\n        sum_ = sum_ + 1\n        assert_(sum_ == n + 2)",
      "        k = n + 1\n        assert_(k == self.k)",
    ].each do |body|
      _status, found = parse_only(py(body), 'Trail.runar.py')
      assert_equal [], found, "unexpected collision for #{body.inspect}"
    end
  end
end
