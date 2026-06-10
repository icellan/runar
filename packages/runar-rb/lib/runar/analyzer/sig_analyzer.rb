# frozen_string_literal: true

require_relative 'types'
require_relative 'path_analyzer'

module Runar
  module Analyzer
    # Signature hygiene (spec §9).
    module SigAnalyzer
      def self.analyze(ops, paths)
        findings = []

        # NO_SIG_CHECK: one per reachable path with hasCheckSig == false.
        paths.each do |path|
          next unless path[:reachable]
          next if path[:has_check_sig]
          findings << {
            severity: 'warning',
            code: 'NO_SIG_CHECK',
            message: 'Execution path has no signature verification (OP_CHECKSIG/OP_CHECKMULTISIG)',
            path: path[:description]
          }
        end

        # CHECKSIG_RESULT_DROPPED.
        ops.each_with_index do |op, i|
          next unless op[:opcode] == 0xac || op[:opcode] == 0xae
          next_op = ops[i + 1]
          next unless next_op && next_op[:opcode] == 0x75
          findings << {
            severity: 'warning',
            code: 'CHECKSIG_RESULT_DROPPED',
            message: "#{op[:name]} result is dropped by #{next_op[:name]} — signature check has no effect",
            offset: op[:offset],
            opcode: op[:name]
          }
        end

        findings
      end
    end
  end
end
