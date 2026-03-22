# frozen_string_literal: true

# Runar SDK — native Ruby code generation from compiled artifacts.
#
# Generates typed Ruby wrapper classes from RunarArtifact, mirroring the
# template-based approach used by the TypeScript, Go, Rust, and Python SDKs.
# Zero external dependencies.

require_relative 'types'

module Runar
  module SDK
    module Codegen
      # -----------------------------------------------------------------------
      # Minimal Mustache renderer
      # -----------------------------------------------------------------------
      # Supports: {{var}}, {{#section}}...{{/section}}, {{^section}}...{{/section}}
      # No HTML escaping, no partials, no lambdas.

      SECTION_RE = /\{\{([#^])(\w+(?:\.\w+)*)\}\}([\s\S]*?)\{\{\/\2\}\}/
      VAR_RE     = /\{\{(\w+(?:\.\w+)*|\.)\}\}/

      private_constant :SECTION_RE, :VAR_RE

      module_function

      def resolve(context, key)
        return context['.'] if key == '.'

        parts = key.split('.')
        current = context
        parts.each do |part|
          return nil if current.nil?
          return nil unless current.is_a?(Hash)

          current = current[part]
        end
        current
      end

      def render_section(template, context)
        result = template
        changed = true

        while changed
          changed = false
          result = result.gsub(SECTION_RE) do
            changed = true
            section_type = ::Regexp.last_match(1)
            key          = ::Regexp.last_match(2)
            body         = ::Regexp.last_match(3)
            value        = resolve(context, key)

            if section_type == '^'
              # Inverted section: render if falsy / empty list
              if !value || (value.is_a?(Array) && value.empty?)
                render_section(body, context)
              else
                ''
              end
            elsif value.is_a?(Array)
              value.map do |item|
                if item.is_a?(Hash)
                  render_section(body, context.merge(item))
                else
                  render_section(body, context.merge('.' => item))
                end
              end.join
            elsif value.is_a?(Hash)
              render_section(body, context.merge(value))
            elsif value
              render_section(body, context)
            else
              ''
            end
          end
        end

        # Variable interpolation
        result.gsub(VAR_RE) do
          key = ::Regexp.last_match(1)
          value = resolve(context, key)
          value.nil? ? '' : value.to_s
        end
      end

      def render_mustache(template, context)
        render_section(template, context)
      end

      # -----------------------------------------------------------------------
      # Type mapping
      # -----------------------------------------------------------------------

      RUBY_TYPE_MAP = {
        'bigint'          => 'Integer',
        'boolean'         => 'Boolean',
        'Sig'             => 'String',
        'PubKey'          => 'String',
        'ByteString'      => 'String',
        'Addr'            => 'String',
        'Ripemd160'       => 'String',
        'Sha256'          => 'String',
        'Point'           => 'String',
        'SigHashPreimage' => 'String',
      }.freeze

      private_constant :RUBY_TYPE_MAP

      def map_type(abi_type)
        RUBY_TYPE_MAP.fetch(abi_type, 'Object')
      end

      # -----------------------------------------------------------------------
      # Name conversion utilities
      # -----------------------------------------------------------------------

      def to_snake_case(name)
        name
          .gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
          .gsub(/([a-z0-9])([A-Z])/, '\1_\2')
          .downcase
      end

      def to_pascal_case(name)
        return name if name.empty?

        name[0].upcase + name[1..]
      end

      SNAKE_RESERVED = %w[connect deploy contract get_locking_script].to_set.freeze
      private_constant :SNAKE_RESERVED

      def safe_method_name(name)
        snake = to_snake_case(name)
        SNAKE_RESERVED.include?(snake) ? "call_#{snake}" : snake
      end

      # -----------------------------------------------------------------------
      # Param classification
      # -----------------------------------------------------------------------

      def classify_params(method, is_stateful)
        method.params.map do |p|
          hidden = p.type == 'Sig' ||
                   (is_stateful && (
                     p.type == 'SigHashPreimage' ||
                     p.name == '_changePKH' ||
                     p.name == '_changeAmount' ||
                     p.name == '_newAmount'
                   ))
          {
            'name'     => p.name,
            'abi_type' => p.type,
            'rb_type'  => map_type(p.type),
            'hidden'   => hidden,
          }
        end
      end

      def get_user_params(method, is_stateful)
        classify_params(method, is_stateful).reject { |p| p['hidden'] }
      end

      def get_sdk_arg_params(method, is_stateful)
        classified = classify_params(method, is_stateful)
        return classified unless is_stateful

        classified.reject do |p|
          p['abi_type'] == 'SigHashPreimage' ||
            p['name'] == '_changePKH' ||
            p['name'] == '_changeAmount' ||
            p['name'] == '_newAmount'
        end
      end

      # -----------------------------------------------------------------------
      # Terminal detection
      # -----------------------------------------------------------------------

      def terminal_method?(method, is_stateful)
        return true unless is_stateful
        return method.is_terminal unless method.is_terminal.nil?

        # Fallback: terminal if no _changePKH param
        method.params.none? { |p| p.name == '_changePKH' }
      end

      # -----------------------------------------------------------------------
      # Artifact analysis
      # -----------------------------------------------------------------------

      def stateful_artifact?(artifact)
        !artifact.state_fields.empty?
      end

      def get_public_methods(artifact)
        artifact.abi.methods.select(&:is_public)
      end

      # -----------------------------------------------------------------------
      # Context builder
      # -----------------------------------------------------------------------

      def build_codegen_context(artifact) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        is_stateful    = stateful_artifact?(artifact)
        public_methods = get_public_methods(artifact)

        has_stateful_methods = is_stateful &&
                               public_methods.any? { |m| !terminal_method?(m, is_stateful) }
        has_terminal_methods = public_methods.any? { |m| terminal_method?(m, is_stateful) }

        # Constructor params
        ctor_params = artifact.abi.constructor_params
        constructor_params = ctor_params.each_with_index.map do |p, i|
          {
            'name'    => to_snake_case(p.name),
            'type'    => map_type(p.type),
            'abiType' => p.type,
            'isLast'  => i == ctor_params.length - 1,
          }
        end

        constructor_args_expr = constructor_params.map { |p| p['name'] }.join(', ')

        # Methods
        methods = public_methods.map do |method|
          user_params_raw = get_user_params(method, is_stateful)
          sdk_args_raw    = get_sdk_arg_params(method, is_stateful)
          terminal        = terminal_method?(method, is_stateful)
          method_name     = safe_method_name(method.name)

          user_params = user_params_raw.each_with_index.map do |p, i|
            {
              'name'    => to_snake_case(p['name']),
              'type'    => p['rb_type'],
              'abiType' => p['abi_type'],
              'isLast'  => i == user_params_raw.length - 1,
            }
          end

          # SDK args expression
          sdk_args_parts = sdk_args_raw.map do |p|
            p['hidden'] ? 'nil' : to_snake_case(p['name'])
          end
          sdk_args_expr = sdk_args_parts.join(', ')

          # Sig params (for prepare/finalize)
          sig_params_raw = sdk_args_raw.select { |p| p['abi_type'] == 'Sig' }
          sig_params = sig_params_raw.each_with_index.map do |sp, i|
            idx = sdk_args_raw.index { |p| p['name'] == sp['name'] }
            {
              'name'     => to_snake_case(sp['name']),
              'argIndex' => idx,
              'isLast'   => i == sig_params_raw.length - 1,
            }
          end

          sig_entries_expr = sig_params.map { |sp| "#{sp['argIndex']} => #{sp['name']}" }.join(', ')

          # Prepare params (user params minus Sig)
          prepare_user_params = user_params.reject { |p| p['abiType'] == 'Sig' }
          prepare_user_params = prepare_user_params.each_with_index.map do |p, i|
            p.merge('isLast' => i == prepare_user_params.length - 1)
          end

          {
            'originalName'       => method.name,
            'name'               => method_name,
            'capitalizedName'    => to_pascal_case(method.name),
            'isTerminal'         => terminal,
            'isStatefulMethod'   => !terminal && is_stateful,
            'hasSigParams'       => !sig_params.empty?,
            'hasUserParams'      => !user_params.empty?,
            'userParams'         => user_params,
            'sdkArgsExpr'        => sdk_args_expr,
            'sigParams'          => sig_params,
            'sigEntriesExpr'     => sig_entries_expr,
            'hasPrepareUserParams' => !prepare_user_params.empty?,
            'prepareUserParams'  => prepare_user_params,
          }
        end

        {
          'contractName'         => artifact.contract_name,
          'contractNameSnake'    => to_snake_case(artifact.contract_name),
          'isStateful'           => is_stateful,
          'hasStatefulMethods'   => has_stateful_methods,
          'hasTerminalMethods'   => has_terminal_methods,
          'hasConstructorParams' => !constructor_params.empty?,
          'constructorParams'    => constructor_params,
          'constructorArgsExpr'  => constructor_args_expr,
          'methods'              => methods,
        }
      end

      # -----------------------------------------------------------------------
      # Ruby template
      # -----------------------------------------------------------------------

      RUBY_TEMPLATE = <<~'MUSTACHE'
        # Generated by: runar codegen
        # Source: {{contractName}}
        # Do not edit manually.

        # frozen_string_literal: true

        require 'runar/sdk'

        module Runar
          module Contracts
        {{#hasTerminalMethods}}
            # Terminal output -- accepts address (converted to P2PKH) or raw script_hex.
            TerminalOutput = Struct.new(:satoshis, :address, :script_hex, keyword_init: true) do
              def initialize(satoshis:, address: '', script_hex: '')
                super
              end
            end unless defined?(TerminalOutput)

            def self.resolve_outputs(outputs)
              outputs.map do |o|
                script = o.script_hex.to_s.empty? ? Runar::SDK.build_p2pkh_script(o.address) : o.script_hex
                Runar::SDK::TerminalOutput.new(script_hex: script, satoshis: o.satoshis)
              end
            end

        {{/hasTerminalMethods}}
        {{#hasStatefulMethods}}
            # Options for stateful method calls on {{contractName}}.
            {{contractName}}StatefulCallOptions = Struct.new(
              :satoshis, :change_address, :change_pub_key, :new_state, :outputs,
              keyword_init: true
            ) do
              def initialize(satoshis: 0, change_address: '', change_pub_key: '', new_state: nil, outputs: nil)
                super
              end

              def to_call_options
                Runar::SDK::CallOptions.new(
                  satoshis: satoshis.positive? ? satoshis : nil,
                  change_address: change_address.empty? ? nil : change_address,
                  change_pub_key: change_pub_key.empty? ? nil : change_pub_key,
                  new_state: new_state,
                  outputs: outputs
                )
              end
            end unless defined?({{contractName}}StatefulCallOptions)

        {{/hasStatefulMethods}}
            class {{contractName}}Contract
              attr_reader :contract

        {{#hasConstructorParams}}
              def initialize(artifact, {{#constructorParams}}{{name}}:{{^isLast}}, {{/isLast}}{{/constructorParams}})
                @contract = Runar::SDK::RunarContract.new(artifact, [{{constructorArgsExpr}}])
              end
        {{/hasConstructorParams}}
        {{^hasConstructorParams}}
              def initialize(artifact)
                @contract = Runar::SDK::RunarContract.new(artifact, [])
              end
        {{/hasConstructorParams}}

              def self.from_txid(artifact, txid, output_index, provider)
                inner = Runar::SDK::RunarContract.from_txid(artifact, txid, output_index, provider)
                instance = allocate
                instance.instance_variable_set(:@contract, inner)
                instance
              end

              def connect(provider, signer)
                @contract.connect(provider, signer)
              end

              def deploy(provider: nil, signer: nil, options: nil)
                @contract.deploy(provider, signer, options)
              end

              def get_locking_script
                @contract.get_locking_script
              end

        {{#methods}}
              def {{name}}({{#userParams}}{{name}}:{{^isLast}}, {{/isLast}}{{/userParams}}{{#hasUserParams}}, {{/hasUserParams}}{{#isStatefulMethod}}options: nil, {{/isStatefulMethod}}{{#isTerminal}}outputs: nil, {{/isTerminal}}provider: nil, signer: nil)
        {{#isTerminal}}
                call_opts = outputs ? Runar::SDK::CallOptions.new(terminal_outputs: Runar::Contracts.resolve_outputs(outputs)) : nil
                @contract.call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)
        {{/isTerminal}}
        {{#isStatefulMethod}}
                call_opts = options&.to_call_options
                @contract.call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)
        {{/isStatefulMethod}}
              end

        {{#hasSigParams}}
              def prepare_{{name}}({{#prepareUserParams}}{{name}}:{{^isLast}}, {{/isLast}}{{/prepareUserParams}}{{#hasPrepareUserParams}}, {{/hasPrepareUserParams}}{{#isStatefulMethod}}options: nil, {{/isStatefulMethod}}{{#isTerminal}}outputs: nil, {{/isTerminal}}provider: nil, signer: nil)
        {{#isTerminal}}
                call_opts = outputs ? Runar::SDK::CallOptions.new(terminal_outputs: Runar::Contracts.resolve_outputs(outputs)) : nil
                @contract.prepare_call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)
        {{/isTerminal}}
        {{#isStatefulMethod}}
                call_opts = options&.to_call_options
                @contract.prepare_call('{{originalName}}', [{{sdkArgsExpr}}], provider, signer, call_opts)
        {{/isStatefulMethod}}
              end

              def finalize_{{name}}(prepared, {{#sigParams}}{{name}}:{{^isLast}}, {{/isLast}}{{/sigParams}}, provider: nil)
                @contract.finalize_call(prepared, { {{sigEntriesExpr}} }, provider)
              end

        {{/hasSigParams}}
        {{/methods}}
            end
          end
        end
      MUSTACHE

      private_constant :RUBY_TEMPLATE

      # -----------------------------------------------------------------------
      # Public API
      # -----------------------------------------------------------------------

      # Generate a typed Ruby wrapper class from a compiled Runar artifact.
      #
      # The generated class wraps +RunarContract+ and exposes typed methods
      # for each public contract method, with appropriate options types for
      # terminal vs state-mutating methods.
      #
      # @param artifact [RunarArtifact] a compiled Runar artifact
      # @return [String] generated Ruby source code
      def generate_ruby(artifact)
        context = build_codegen_context(artifact)
        render_mustache(RUBY_TEMPLATE, context)
      end
    end
  end
end
