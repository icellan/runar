# frozen_string_literal: true

require 'minitest/autorun'
require 'json'

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'runar_compiler'

module ConformanceFixture
  CONFORMANCE_DIR = File.expand_path('../../../conformance/tests', __dir__)

  # Resolve a per-format source file for a conformance fixture by reading
  # source.json. After the source.json migration the per-format files no
  # longer live inside conformance/tests/<fixture>/ — they live under
  # examples/ and source.json maps each `.runar.<ext>` to a relative path.
  #
  # Returns absolute path; raises if source.json missing or ext not declared.
  def self.resolve(fixture_name, ext)
    config_path = File.join(CONFORMANCE_DIR, fixture_name, 'source.json')
    raise "source.json missing: #{config_path}" unless File.exist?(config_path)

    config = JSON.parse(File.read(config_path))
    rel = config.dig('sources', ext)
    rel = config['path'] if rel.nil? && ext == '.runar.ts'
    if rel.nil?
      raise "source.json for fixture '#{fixture_name}' has no entry for #{ext}"
    end

    File.expand_path(rel, File.dirname(config_path))
  end

  # Returns true when ext is intentionally opted-out via parserSkip[].
  def self.parser_skip?(fixture_name, ext)
    config_path = File.join(CONFORMANCE_DIR, fixture_name, 'source.json')
    return false unless File.exist?(config_path)

    config = JSON.parse(File.read(config_path))
    Array(config['parserSkip']).include?(ext)
  end

  # Returns true when the fixture's source.json "compilers" allowlist
  # (conformance/README.md "Per-fixture compiler allowlist") exists and
  # does not include compiler_id -- i.e. compiler_id is not a conformance
  # target for this fixture and should be skipped, not failed. Mirrors
  # `conformance/runner/runner.ts::readFixtureCompilerAllowlist` and
  # test_conformance_goldens.rb's `read_compiler_allowlist` (F-264).
  #
  # No rescue around JSON.parse: a malformed source.json must surface
  # (F-264 fail-closed), not be silently treated as "no allowlist".
  def self.compiler_excluded?(fixture_name, compiler_id)
    config_path = File.join(CONFORMANCE_DIR, fixture_name, 'source.json')
    return false unless File.exist?(config_path)

    config = JSON.parse(File.read(config_path))
    allowlist = config['compilers']
    allowlist.is_a?(Array) && !allowlist.include?(compiler_id)
  end
end
