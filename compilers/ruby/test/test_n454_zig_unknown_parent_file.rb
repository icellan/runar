# frozen_string_literal: true

# N-454 — the .runar.zig parser's "unknown parent class" diagnostic.
#
# It interpolated @file, an ivar the Zig parser never sets (the name lives in
# @file_name), so the diagnostic began ":<line>:<col>:" with no file name, and
# carried no structured location. Go and TS attach the file/line/col as the
# diagnostic location; this test pins the same for Ruby.
#
# What this proves: refusing an unknown base class names the source file, with
# the parent token's line and column, in the formatted message and in loc.
# What it does not prove: other diagnostics in the Zig parser (they already use
# @file_name), other tiers, or emitted bytes.

require_relative 'test_helper'

class TestN454ZigUnknownParentFile < Minitest::Test
  require 'runar_compiler/frontend/parser_zig'

  SOURCE = <<~ZIG
    const runar = @import("runar");

    pub const Bad = struct {
        pub const Contract = runar.Bogus;

        alpha: runar.Bigint,

        pub fn check(self: Bad) void {
            runar.assert(self.alpha > 0);
        }
    };
  ZIG

  def test_unknown_parent_class_diagnostic_names_the_file
    result = RunarCompiler.send(:_parse_source, SOURCE, 'Bad.runar.zig')
    diag = result.errors.find { |e| e.message.include?('unknown parent class') }
    refute_nil diag, 'expected an unknown parent class diagnostic'
    assert_includes diag.message, "'Bogus'"
    assert_equal 'Bad.runar.zig', diag.loc.file
    assert_equal 4, diag.loc.line
    assert_match(/\ABad\.runar\.zig:4:\d+: /, diag.format_message)
  end
end
