# frozen_string_literal: true

require 'json'
require_relative 'analyzer/types'
require_relative 'analyzer/script_parser'
require_relative 'analyzer/stack_analyzer'
require_relative 'analyzer/path_analyzer'
require_relative 'analyzer/sig_analyzer'
require_relative 'analyzer/opcode_concerns'

module Runar
  # Bitcoin Script static analyzer. See spec/script-analyzer-format.md.
  module Analyzer
    module_function

    # Collapse raw_script spans into synthetic RAW_SPAN steps (spec §12).
    # `spans` is an Array of Hashes with :offset, :length, :in_arity, :out_arity.
    def collapse_raw_script_spans(ops, spans)
      return ops if spans.nil? || spans.empty?
      sorted = spans.sort_by { |s| s[:offset] }
      output = []
      span_idx = 0
      ops.each do |op|
        # Advance past spans that end before this opcode.
        while span_idx < sorted.length &&
              (sorted[span_idx][:offset] + sorted[span_idx][:length]) <= op[:offset]
          span_idx += 1
        end

        if span_idx >= sorted.length
          output << op
          next
        end

        span = sorted[span_idx]
        span_end = span[:offset] + span[:length]

        if op[:offset] + op[:size] <= span[:offset]
          output << op
          next
        end

        if op[:offset] >= span[:offset] && op[:offset] + op[:size] <= span_end
          # Inside the span: drop, emit synthetic once.
          last = output.last
          unless last && last[:opcode] == -1 && last[:offset] == span[:offset]
            output << {
              offset: span[:offset],
              opcode: -1,
              name: 'RAW_SPAN',
              size: span[:length],
              raw_span_arity: [span[:in_arity], span[:out_arity]]
            }
          end
        else
          # Partial overlap: drop, ensure synthetic emitted once.
          last = output.last
          unless last && last[:opcode] == -1 && last[:offset] == span[:offset]
            output << {
              offset: span[:offset],
              opcode: -1,
              name: 'RAW_SPAN',
              size: span[:length],
              raw_span_arity: [span[:in_arity], span[:out_arity]]
            }
          end
        end
      end
      output
    end

    # Public entry. Returns a Hash (raw analysis result; not serialized JSON).
    def analyze_script(hex_script, options = {})
      normalized = hex_script.gsub(/\s/, '').downcase
      script_size = normalized.length / 2

      if script_size == 0
        return {
          script: '',
          script_size: 0,
          findings: [{
            severity: 'error',
            code: 'INVALID_TERMINAL_STACK',
            message: 'Empty script — no opcodes to execute'
          }],
          paths: [],
          summary: {
            total_paths: 0,
            reachable_paths: 0,
            paths_with_check_sig: 0,
            paths_without_check_sig: 0,
            max_stack_depth: 0,
            script_size_bytes: 0
          }
        }
      end

      ops = ScriptParser.parse(normalized)
      if options[:raw_script_spans] && !options[:raw_script_spans].empty?
        ops = collapse_raw_script_spans(ops, options[:raw_script_spans])
      end

      all_findings = []

      # Step 1: path analysis.
      path_result = PathAnalyzer.analyze(ops)
      paths = path_result[:paths]
      all_findings.concat(path_result[:findings])

      has_unbalanced = path_result[:findings].any? { |f| f[:code] == 'UNBALANCED_IF_ENDIF' }

      # Step 2: linear fallback if no paths and no structural error.
      if paths.empty? && !has_unbalanced
        # Note: filter control-flow ops defensively.
        collected = ops.reject { |op| [0x63, 0x64, 0x67, 0x68].include?(op[:opcode]) }
        linear = StackAnalyzer.analyze(collected, initial_depth: 0)
        all_findings.concat(linear[:findings])
      end

      # Step 3: sig hygiene.
      all_findings.concat(SigAnalyzer.analyze(ops, paths))

      # Step 4: opcode concerns.
      all_findings.concat(OpcodeConcerns.analyze(ops, script_size))

      # Stable sort by (severity_rank, offset_rank).
      indexed = all_findings.each_with_index.to_a
      indexed.sort_by! do |(f, i)|
        sev = SEVERITY_RANK[f[:severity]] || 99
        # JS uses Infinity for missing offset; we emulate with a very
        # large number that sorts after any real offset.
        off = f[:offset].nil? ? Float::INFINITY : f[:offset]
        [sev, off, i]
      end
      sorted_findings = indexed.map(&:first)

      # Summary.
      total_paths = paths.length
      reachable = paths.count { |p| p[:reachable] }
      with_check = paths.count { |p| p[:reachable] && p[:has_check_sig] }
      without_check = paths.count { |p| p[:reachable] && !p[:has_check_sig] }
      # Spec §8.3 says max of stackDepthAtEnd "defaulting to 0 if no
      # paths" — but the goldens consistently show maxStackDepth = 0
      # whenever all stackDepthAtEnd values are negative. The TS
      # reference appears to use Math.max(0, ...depths) with an initial
      # accumulator of 0, not max-of-array. We replicate that here.
      max_depth = ([0] + paths.map { |p| p[:stack_depth_at_end] }).max

      {
        script: normalized,
        script_size: script_size,
        findings: sorted_findings,
        paths: paths,
        summary: {
          total_paths: total_paths,
          reachable_paths: reachable,
          paths_with_check_sig: with_check,
          paths_without_check_sig: without_check,
          max_stack_depth: max_depth,
          script_size_bytes: script_size
        }
      }
    end

    # Serialize analysis result to canonical JSON per spec §3.5.
    # Output ends with exactly one trailing newline.
    def to_canonical_json(result)
      top = {}
      top['script'] = result[:script]
      top['scriptSize'] = result[:script_size]
      top['findings'] = result[:findings].map { |f| finding_to_h(f) }
      top['paths'] = result[:paths].map { |p| path_to_h(p) }
      top['summary'] = summary_to_h(result[:summary])
      JSON.pretty_generate(top) + "\n"
    end

    def finding_to_h(f)
      h = {}
      h['severity'] = f[:severity]
      h['code'] = f[:code]
      h['message'] = f[:message]
      h['offset'] = f[:offset] unless f[:offset].nil?
      h['opcode'] = f[:opcode] unless f[:opcode].nil?
      h['path'] = f[:path] unless f[:path].nil?
      h
    end

    def path_to_h(p)
      {
        'id' => p[:id],
        'description' => p[:description],
        'branchChoices' => p[:branch_choices],
        'reachable' => p[:reachable],
        'hasCheckSig' => p[:has_check_sig],
        'stackDepthAtEnd' => p[:stack_depth_at_end]
      }
    end

    def summary_to_h(s)
      {
        'totalPaths' => s[:total_paths],
        'reachablePaths' => s[:reachable_paths],
        'pathsWithCheckSig' => s[:paths_with_check_sig],
        'pathsWithoutCheckSig' => s[:paths_without_check_sig],
        'maxStackDepth' => s[:max_stack_depth],
        'scriptSizeBytes' => s[:script_size_bytes]
      }
    end
  end
end
