# frozen_string_literal: true

# Runar compile_check — validates Ruby contracts through the Runar frontend.
#
# This is a placeholder that will use the Ruby compiler once it's implemented.
# For now, it validates that the source file exists and has basic Ruby contract
# structure.

module Runar
  def self.compile_check(source_or_path, file_name = nil)
    if !source_or_path.include?("\n") && File.file?(source_or_path)
      source = File.read(source_or_path)
      file_name ||= source_or_path
    else
      source = source_or_path
      file_name ||= 'contract.runar.rb'
    end

    # Basic structural validation
    unless source.include?('class ')
      raise "No class declaration found in #{file_name}"
    end

    unless source.include?('SmartContract')
      raise "Contract class must extend SmartContract or StatefulSmartContract in #{file_name}"
    end

    true
  end
end
