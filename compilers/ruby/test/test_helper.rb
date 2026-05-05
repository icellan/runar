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
end
