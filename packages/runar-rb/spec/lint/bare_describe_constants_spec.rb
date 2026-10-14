# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

# N-269: assigning `CONST = value` directly inside an `RSpec.describe` (or
# `context`/`it`) block does NOT scope that constant to the block. Ruby's
# constant-assignment scope follows lexical `class`/`module` nesting, not
# `do...end` — a block opens no constant scope, even though it changes
# `self`. So `FOO = 1` written anywhere inside `RSpec.describe('x') { ... }`
# binds `Object::FOO`, exactly as if it were written at the top of the
# file. Two spec files that each bind the same bare name collide when both
# load into the same rspec process: whichever file loads second silently
# wins for every unqualified reference to that name for the rest of the
# run. This exact mechanism bit `issue100_spec.rb` against
# `n227_zero_mutable_field_fee_floor_spec.rb`'s bare `SRC` (fixed in
# CK18-FU8 by renaming to `I100_SRC`); `REPO_ROOT` was a second, still-live
# instance of the same bug (`compile_check_spec.rb` vs
# `analyzer/conformance_spec.rb`), fixed alongside this guard.
#
# This spec parses every other spec file's AST (`RubyVM::AbstractSyntaxTree`,
# stdlib, MRI-only) and flags any constant-assignment node (`:CDECL`) that
# is not lexically nested inside a `class`/`module`/`class << self` body,
# then fails if the same bare name is bound by more than one file.
RSpec.describe 'Ruby spec files do not collide on bare top-level constants' do
  def bare_constant_assignments(path)
    ast = RubyVM::AbstractSyntaxTree.parse_file(path)
    found = []
    walk = lambda do |node, in_class_or_module|
      return unless node.is_a?(RubyVM::AbstractSyntaxTree::Node)

      if node.type == :CDECL
        name = node.children.find { |child| child.is_a?(Symbol) }
        found << [name, node.first_lineno] if name && !in_class_or_module
      end

      nested = in_class_or_module || %i[CLASS MODULE SCLASS].include?(node.type)
      node.children.each { |child| walk.call(child, nested) if child.is_a?(RubyVM::AbstractSyntaxTree::Node) }
    end
    walk.call(ast, false)
    found
  end

  # Returns { const_name => ["path:line", ...] } restricted to names bound
  # by more than one DISTINCT file (same-file reassignment is a separate,
  # pre-existing Ruby warning and not what this guard is about).
  def bare_constant_collisions(paths)
    by_name = Hash.new { |hash, key| hash[key] = [] }
    paths.each do |path|
      bare_constant_assignments(path).each do |name, line|
        by_name[name] << "#{path}:#{line}"
      end
    end
    by_name.select { |_name, locations| locations.map { |loc| loc.split(':').first }.uniq.size > 1 }
  end

  # Proves the detector itself fires on a real duplicate and isn't vacuous
  # — without this, the suite-wide check below could pass merely because
  # nothing in the real tree happens to collide right now.
  it 'detects a seeded duplicate bare constant across two files' do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'a_spec.rb'), "RSpec.describe('a') do\n  DUPTEST = 1\nend\n")
      File.write(File.join(dir, 'b_spec.rb'), "RSpec.describe('b') do\n  DUPTEST = 2\nend\n")

      collisions = bare_constant_collisions(Dir.glob(File.join(dir, '*.rb')).sort)

      expect(collisions.keys).to eq([:DUPTEST])
    end
  end

  it 'finds no two spec files binding the same bare top-level constant' do
    spec_root = File.expand_path(File.join(__dir__, '..'))
    spec_files = Dir.glob(File.join(spec_root, '**', '*.rb')).sort

    collisions = bare_constant_collisions(spec_files)

    message = collisions.map { |name, locations| "#{name} bound at: #{locations.join(', ')}" }.join("\n")
    expect(collisions).to be_empty, "bare top-level constant collisions found:\n#{message}"
  end
end
