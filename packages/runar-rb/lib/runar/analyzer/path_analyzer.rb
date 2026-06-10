# frozen_string_literal: true

require_relative 'types'
require_relative 'stack_analyzer'

module Runar
  module Analyzer
    # Path enumeration + per-path stack/sig analysis. See spec §7.
    module PathAnalyzer
      # Spec v1.2 §5.1: render the path count symbolically when
      # 2^num_branches overflows the canonical TS reference's safe-integer
      # range.
      LARGE_BRANCH_THRESHOLD = 53

      # Match IF/NOTIF/ELSE/ENDIF. Returns {branches:, findings:, structural_error:}.
      # branches: [{if_idx:, else_idx:, endif_idx:, is_notif:}]
      def self.match_branches(ops)
        stack = []
        branches = []
        findings = []
        structural_error = false

        ops.each_with_index do |op, i|
          case op[:opcode]
          when 0x63, 0x64 # OP_IF, OP_NOTIF
            stack << { if_idx: i, else_idx: -1, is_notif: op[:opcode] == 0x64 }
          when 0x67 # OP_ELSE
            if stack.empty?
              findings << {
                severity: 'error',
                code: 'UNBALANCED_IF_ENDIF',
                message: 'OP_ELSE without matching OP_IF',
                offset: op[:offset],
                opcode: op[:name]
              }
              structural_error = true
            else
              stack.last[:else_idx] = i
            end
          when 0x68 # OP_ENDIF
            if stack.empty?
              findings << {
                severity: 'error',
                code: 'UNBALANCED_IF_ENDIF',
                message: 'OP_ENDIF without matching OP_IF',
                offset: op[:offset],
                opcode: op[:name]
              }
              structural_error = true
            else
              frame = stack.pop
              branches << {
                if_idx: frame[:if_idx],
                else_idx: frame[:else_idx],
                endif_idx: i,
                is_notif: frame[:is_notif]
              }
            end
          end
        end

        # Any unclosed IF/NOTIF frames.
        stack.each do |frame|
          op = ops[frame[:if_idx]]
          findings << {
            severity: 'error',
            code: 'UNBALANCED_IF_ENDIF',
            message: "#{op[:name]} at offset #{op[:offset]} has no matching OP_ENDIF",
            offset: op[:offset],
            opcode: op[:name]
          }
          structural_error = true
        end

        { branches: branches, findings: findings, structural_error: structural_error }
      end

      # Indices in ops (in source order) of OP_IF / OP_NOTIF.
      def self.if_op_indices(ops)
        out = []
        ops.each_with_index do |op, i|
          out << i if op[:opcode] == 0x63 || op[:opcode] == 0x64
        end
        out
      end

      # For a path-traversal: given the opcodes and a choices vector (in
      # source order of IF/NOTIF), collect the opcodes that execute. The
      # IF/NOTIF/ELSE/ENDIF themselves are NOT included.
      def self.collect_path_opcodes(ops, choices)
        result = []
        choice_idx = 0
        # Stack of skip-modes for nested IFs we entered. Each entry is
        # {endif_idx: i, in_skipped_else: bool}.
        # We use a position-based traversal.
        i = 0
        n = ops.length
        # We need to find matching ELSE/ENDIF by scanning. Pre-compute
        # match arrays for efficiency.
        match = compute_matches(ops)

        while i < n
          op = ops[i]
          b = op[:opcode]

          if b == 0x63 || b == 0x64
            # Determine choice for this IF.
            choice = choice_idx < choices.length ? choices[choice_idx] : true
            choice_idx += 1
            else_idx = match[:else_of][i]
            endif_idx = match[:endif_of][i]
            if choice
              # Execute THEN body: opcodes (i+1 .. else_idx-1) or (i+1 .. endif_idx-1)
              then_end = else_idx >= 0 ? else_idx : endif_idx
              j = i + 1
              while j < then_end
                inner = ops[j]
                if inner[:opcode] == 0x63 || inner[:opcode] == 0x64
                  # Nested IF: recurse handling by continuing the outer loop,
                  # but we need to handle nesting properly. Use a sub-collect.
                  sub, consumed_choices = collect_nested(ops, j, choices, choice_idx, match)
                  result.concat(sub)
                  choice_idx += consumed_choices
                  j = match[:endif_of][j] + 1
                else
                  result << inner unless control_flow?(inner)
                  j += 1
                end
              end
              i = endif_idx + 1
            else
              # Skip THEN body, execute ELSE body if present.
              if else_idx >= 0
                j = else_idx + 1
                while j < endif_idx
                  inner = ops[j]
                  if inner[:opcode] == 0x63 || inner[:opcode] == 0x64
                    sub, consumed_choices = collect_nested(ops, j, choices, choice_idx, match)
                    result.concat(sub)
                    choice_idx += consumed_choices
                    j = match[:endif_of][j] + 1
                  else
                    result << inner unless control_flow?(inner)
                    j += 1
                  end
                end
              end
              # Still need to skip past any IF/NOTIF inside the THEN
              # body for the choice_idx counter. Count nested IFs in
              # the skipped THEN region.
              then_end = else_idx >= 0 ? else_idx : endif_idx
              choice_idx += count_ifs(ops, i + 1, then_end)
              i = endif_idx + 1
            end
          else
            result << op unless control_flow?(op)
            i += 1
          end
        end

        result
      end

      # Helper: count IF/NOTIF in range [from, to).
      def self.count_ifs(ops, from, to)
        c = 0
        (from...to).each do |k|
          b = ops[k][:opcode]
          c += 1 if b == 0x63 || b == 0x64
        end
        c
      end

      # Helper: is this op a control-flow marker?
      def self.control_flow?(op)
        b = op[:opcode]
        b == 0x63 || b == 0x64 || b == 0x67 || b == 0x68
      end

      # Sub-collection starting at a nested IF/NOTIF at index i. Returns
      # [opcodes, consumed_choices].
      def self.collect_nested(ops, i, choices, choice_idx, match)
        result = []
        op = ops[i]
        choice = choice_idx < choices.length ? choices[choice_idx] : true
        consumed = 1
        else_idx = match[:else_of][i]
        endif_idx = match[:endif_of][i]
        if choice
          then_end = else_idx >= 0 ? else_idx : endif_idx
          j = i + 1
          while j < then_end
            inner = ops[j]
            if inner[:opcode] == 0x63 || inner[:opcode] == 0x64
              sub, sub_consumed = collect_nested(ops, j, choices, choice_idx + consumed, match)
              result.concat(sub)
              consumed += sub_consumed
              j = match[:endif_of][j] + 1
            else
              result << inner unless control_flow?(inner)
              j += 1
            end
          end
        else
          if else_idx >= 0
            j = else_idx + 1
            while j < endif_idx
              inner = ops[j]
              if inner[:opcode] == 0x63 || inner[:opcode] == 0x64
                sub, sub_consumed = collect_nested(ops, j, choices, choice_idx + consumed, match)
                result.concat(sub)
                consumed += sub_consumed
                j = match[:endif_of][j] + 1
              else
                result << inner unless control_flow?(inner)
                j += 1
              end
            end
          end
          then_end = else_idx >= 0 ? else_idx : endif_idx
          consumed += count_ifs(ops, i + 1, then_end)
        end
        [result, consumed]
      end

      # Pre-compute else_of[i] and endif_of[i] for each IF/NOTIF.
      def self.compute_matches(ops)
        else_of = Array.new(ops.length, -1)
        endif_of = Array.new(ops.length, -1)
        stack = []
        ops.each_with_index do |op, i|
          case op[:opcode]
          when 0x63, 0x64
            stack << i
          when 0x67
            if !stack.empty?
              else_of[stack.last] = i
            end
          when 0x68
            if !stack.empty?
              start = stack.pop
              endif_of[start] = i
            end
          end
        end
        { else_of: else_of, endif_of: endif_of }
      end

      # Build the description string for a path per spec §7.3.
      def self.describe_path(ops, if_indices, choices)
        return 'linear (no branches)' if if_indices.empty?
        parts = if_indices.each_with_index.map do |op_idx, b|
          op = ops[op_idx]
          label = op[:opcode] == 0x64 ? 'NOTIF' : 'IF'
          bool = choices[b] ? 'true' : 'false'
          "#{label}[#{bool}] at #{op[:offset]}"
        end
        parts.join(' -> ')
      end

      # Whether the collected opcode list contains a CHECKSIG/MULTISIG variant.
      def self.has_check_sig?(collected)
        collected.any? { |op| SIG_OPCODES.include?(op[:opcode]) }
      end

      # Whether the collected list contains ANY verification opcode
      # (§7.5).
      def self.has_verification?(collected)
        collected.any? { |op| VERIFICATION_OPCODES.include?(op[:opcode]) }
      end

      # Top-level path analysis. Returns {paths:, findings:}.
      def self.analyze(ops)
        all_findings = []

        match = match_branches(ops)
        all_findings.concat(match[:findings])

        if match[:structural_error]
          return { paths: [], findings: all_findings }
        end

        if_indices = if_op_indices(ops)
        num_branches = if_indices.length

        if num_branches == 0
          # Single linear path.
          collected = ops.reject { |op| control_flow?(op) }
          path_desc = 'linear (no branches)'
          path_findings, depth = analyze_single_path(collected, path_desc)
          all_findings.concat(path_findings)

          path = build_path(0, path_desc, [], collected, depth)

          # Branch-depth findings (none — no branches).
          return { paths: [path], findings: all_findings }
        end

        use_exact_count = num_branches < LARGE_BRANCH_THRESHOLD
        if use_exact_count
          exact = 1 << num_branches
          truncated = exact > MAX_PATHS
          loop_bound = [exact, MAX_PATHS].min
          paths_clause = "2^#{num_branches} = #{exact} paths"
        else
          truncated = true
          loop_bound = MAX_PATHS
          paths_clause = "more than 2^#{LARGE_BRANCH_THRESHOLD} paths"
        end

        if truncated
          all_findings << {
            severity: 'warning',
            code: 'PATHS_TRUNCATED',
            message: "Script has #{num_branches} branch points (#{paths_clause}); analysis truncated to the first 256. Consider reducing branching or splitting the contract into smaller spending paths."
          }
        end

        paths = []
        per_path_findings = []

        loop_bound.times do |combo|
          # `combo` is bounded by MAX_PATHS = 256, so bits at positions
          # >= 8 are mathematically always 0. Clamp to b < 31 to match
          # the canonical TS reference, where JS `>>` would otherwise
          # mask the shift count to 5 bits and wrap.
          choices = Array.new(num_branches) { |b| b < 31 ? ((combo >> b) & 1) == 1 : false }
          collected = collect_path_opcodes(ops, choices)
          desc = describe_path(ops, if_indices, choices)
          findings, depth = analyze_single_path(collected, desc)
          per_path_findings.concat(findings)
          paths << build_path(combo, desc, choices, collected, depth)
        end

        all_findings.concat(per_path_findings)

        # Branch-depth findings (§7.6) — appended after per-path findings.
        match[:branches].each do |branch|
          endif_op = ops[branch[:endif_idx]]
          if branch[:else_idx] < 0
            delta = StackAnalyzer.flat_delta(ops, branch[:if_idx] + 1, branch[:endif_idx])
            next if delta.nil?
            if delta != 0
              all_findings << {
                severity: 'warning',
                code: 'INCONSISTENT_BRANCH_DEPTH',
                message: "OP_IF body has net stack delta #{delta}; without an OP_ELSE the depth after OP_ENDIF depends on the branch condition",
                offset: endif_op[:offset],
                opcode: 'OP_ENDIF'
              }
            end
          else
            then_delta = StackAnalyzer.flat_delta(ops, branch[:if_idx] + 1, branch[:else_idx])
            else_delta = StackAnalyzer.flat_delta(ops, branch[:else_idx] + 1, branch[:endif_idx])
            next if then_delta.nil? || else_delta.nil?
            if then_delta != else_delta
              all_findings << {
                severity: 'warning',
                code: 'INCONSISTENT_BRANCH_DEPTH',
                message: "IF/ELSE branches leave different stack depths (THEN: #{then_delta}, ELSE: #{else_delta}) — code after OP_ENDIF will see a depth that depends on which branch ran",
                offset: endif_op[:offset],
                opcode: 'OP_ENDIF'
              }
            end
          end
        end

        { paths: paths, findings: all_findings }
      end

      # Run stack analysis + UNCONDITIONALLY_SUCCEEDS for one path.
      # Returns [findings, stack_depth_at_end].
      def self.analyze_single_path(collected, path_desc)
        result = StackAnalyzer.analyze(collected, initial_depth: 0)
        findings = result[:findings].map do |f|
          f.merge(path: path_desc)
        end

        if !collected.empty? && !has_verification?(collected)
          findings << {
            severity: 'warning',
            code: 'UNCONDITIONALLY_SUCCEEDS',
            message: 'Execution path has no verification opcode — any unlocking input will satisfy it',
            path: path_desc
          }
        end

        [findings, result[:depth]]
      end

      def self.build_path(id, desc, choices, collected, depth)
        {
          id: id,
          description: desc,
          branch_choices: choices,
          reachable: true,
          has_check_sig: has_check_sig?(collected),
          stack_depth_at_end: depth
        }
      end
    end
  end
end
