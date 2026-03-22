# frozen_string_literal: true

require 'runar'
require 'shellwords'

PROJECT_ROOT = File.expand_path('../..', __dir__).freeze

# Compile a .runar.rb contract through the Runar compiler pipeline.
#
# Uses the TypeScript compiler via node shell-out (same pattern as
# integration/ruby/spec/spec_helper.rb).
#
# @param rel_path [String] path relative to end2end-example/ruby/
# @return [String] compiled artifact JSON
# @raise [RuntimeError] if compilation fails
def compile_contract(rel_path)
  abs_path = File.expand_path(rel_path, __dir__)
  file_name = File.basename(rel_path)

  script = <<~JS
    const { compile } = require('#{PROJECT_ROOT}/packages/runar-compiler/dist/index.js');
    const fs = require('fs');
    const source = fs.readFileSync(#{abs_path.inspect}, 'utf-8');
    const result = compile(source, { fileName: #{file_name.inspect} });
    if (!result.success) { console.error(JSON.stringify(result.diagnostics, null, 2)); process.exit(1); }
    const json = JSON.stringify(result.artifact, (k, v) => typeof v === 'bigint' ? v.toString() + 'n' : v);
    process.stdout.write(json);
  JS

  output = `node -e #{Shellwords.escape(script)} 2>&1`
  status = Process.last_status
  raise "Compilation failed for #{rel_path}:\n#{output}" unless status&.success?

  output
end
