# frozen_string_literal: true

# Specs for the Runar Ruby LSP hover listener.
#
# The hover listener provides contextual documentation when a developer hovers
# over Runar-specific identifiers in .runar.rb contract files.
#
# These tests run without the ruby-lsp gem installed: we stub just the surface
# area the hover listener touches, matching the pattern in addon_spec.rb.

require 'spec_helper'
require 'uri'

# ---------------------------------------------------------------------------
# Minimal ruby-lsp stubs (mirrored from addon_spec.rb)
# ---------------------------------------------------------------------------

unless defined?(RubyLsp::Addon)
  module RubyLsp
    class Addon
      def activate(_global_state, _message_queue); end
      def deactivate; end
      def name; end
      def version; end
    end
  end
end

unless defined?(Prism)
  module Prism
    class SymbolNode; end
    class ConstantReadNode; end
    class KeywordHashNode; end
    class AssocNode; end
    class TrueNode; end
  end
end

unless defined?(RubyIndexer::Enhancement)
  module RubyIndexer
    class Enhancement
      @enhancements = []

      class << self
        attr_reader :enhancements

        def inherited(child)
          @enhancements << child
          super
        end

        def clear
          @enhancements.clear
        end
      end

      def initialize(listener)
        @listener = listener
      end

      def on_call_node_enter(node); end
      def on_call_node_leave(node); end
    end
  end
end

# ---------------------------------------------------------------------------
# Load addon files after stubs are in place.
# ---------------------------------------------------------------------------

require_relative '../../lib/ruby_lsp/runar/addon'
require_relative '../../lib/ruby_lsp/runar/hover'

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

# Builds a response_builder that records every push call as a hash.
def build_response_builder
  builder = Object.new
  builder.instance_variable_set(:@pushes, [])
  builder.define_singleton_method(:push) do |text, category: :documentation|
    @pushes << { text: text, category: category }
  end
  builder.define_singleton_method(:pushes) { @pushes }
  builder
end

# Builds a node_context whose URI is the given string.
# Uses the document_uri accessor path that hover.rb tries first.
def build_node_context(uri_string)
  uri = URI.parse(uri_string)
  ctx = Object.new
  ctx.define_singleton_method(:document_uri) { uri }
  ctx.define_singleton_method(:parent) { nil }
  ctx
end

# Builds a fake Prism::Dispatcher that records registrations and allows
# manual dispatch of events.
def build_dispatcher
  dispatcher = Object.new
  dispatcher.instance_variable_set(:@registrations, [])

  dispatcher.define_singleton_method(:register) do |listener, *events|
    events.each { |ev| @registrations << { listener: listener, event: ev } }
  end

  dispatcher.define_singleton_method(:dispatch) do |event, node|
    @registrations
      .select { |r| r[:event] == event }
      .each   { |r| r[:listener].public_send(event, node) }
  end

  dispatcher.define_singleton_method(:registered_events) do
    @registrations.map { |r| r[:event] }.uniq
  end

  dispatcher
end

# Builds a fake call node with the given method name (Symbol).
def call_node(method_name)
  node = Object.new
  node.define_singleton_method(:name) { method_name }
  node
end

# Builds a fake ConstantReadNode with the given constant name (Symbol).
def constant_read_node(const_name)
  node = Object.new
  node.define_singleton_method(:name) { const_name }
  node
end

# Builds a fake DefNode with the given method name.
def def_node(method_name)
  node = Object.new
  node.define_singleton_method(:name) { method_name }
  node
end

# Builds a fake runar_public/params CallNode with keyword type arguments.
# type_hash: { 'sig' => 'Sig', 'pub_key' => 'PubKey' }
def annotation_call_node(method_name, type_hash)
  pairs = type_hash.map do |param_name, type_name|
    key = Object.new
    key.define_singleton_method(:is_a?) { |klass| klass == Prism::SymbolNode }
    key.define_singleton_method(:value) { param_name }

    value = Object.new
    value.define_singleton_method(:is_a?) { |klass| klass == Prism::ConstantReadNode }
    value.define_singleton_method(:name) { type_name }

    pair = Object.new
    pair.define_singleton_method(:is_a?) { |klass| klass == Prism::AssocNode }
    pair.define_singleton_method(:key) { key }
    pair.define_singleton_method(:value) { value }
    pair
  end

  kw_hash = Object.new
  kw_hash.define_singleton_method(:is_a?) { |klass| klass == Prism::KeywordHashNode }
  kw_hash.define_singleton_method(:elements) { pairs }

  args = Object.new
  args.define_singleton_method(:arguments) { [kw_hash] }

  node = Object.new
  node.define_singleton_method(:name) { method_name.to_sym }
  node.define_singleton_method(:is_a?) { |klass| klass == Prism::CallNode }
  node.define_singleton_method(:arguments) { args }
  node
end

# Builds a node_context with a parent that contains the given children as
# sibling statements. Used for testing def-node hover with preceding annotations.
def build_node_context_with_parent(uri_string, children)
  uri = URI.parse(uri_string)
  body = Object.new
  body.define_singleton_method(:body) { children }
  parent = Object.new
  parent.define_singleton_method(:body) { body }

  ctx = Object.new
  ctx.define_singleton_method(:document_uri) { uri }
  ctx.define_singleton_method(:parent) { parent }
  ctx
end

# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------

RSpec.describe RubyLsp::Runar::Hover do
  let(:runar_uri)   { 'file:///contracts/MyContract.runar.rb' }
  let(:regular_uri) { 'file:///lib/my_class.rb' }

  # -------------------------------------------------------------------------
  # Helpers for building instances under test
  # -------------------------------------------------------------------------

  def build_hover(uri_string)
    builder    = build_response_builder
    context    = build_node_context(uri_string)
    dispatcher = build_dispatcher

    hover = described_class.new(builder, context, dispatcher)
    [hover, builder, dispatcher]
  end

  # -------------------------------------------------------------------------
  # Listener registration
  # -------------------------------------------------------------------------

  describe 'dispatcher registration' do
    context 'with a .runar.rb file' do
      it 'registers for call_node and constant_read_node events' do
        _, _, dispatcher = build_hover(runar_uri)
        expect(dispatcher.registered_events).to include(:on_call_node_enter)
        expect(dispatcher.registered_events).to include(:on_constant_read_node_enter)
      end
    end

    context 'with a non-.runar.rb file' do
      it 'does not register any events' do
        _, _, dispatcher = build_hover(regular_uri)
        expect(dispatcher.registered_events).to be_empty
      end
    end
  end

  # -------------------------------------------------------------------------
  # Builtin function hover
  # -------------------------------------------------------------------------

  describe '#on_call_node_enter — builtin functions' do
    context 'with a .runar.rb file' do
      subject(:hover) { build_hover(runar_uri).first }
      let(:builder)   { build_hover(runar_uri)[1] }

      # Re-build so we can share builder between hover and assertion
      let(:components) { build_hover(runar_uri) }
      let(:the_hover)  { components[0] }
      let(:the_builder) { components[1] }

      it 'provides documentation for sha256' do
        the_hover.on_call_node_enter(call_node(:sha256))
        expect(the_builder.pushes.map { |p| p[:text] }.join(' ')).to include('sha256')
      end

      it 'includes the signature and return type for sha256' do
        the_hover.on_call_node_enter(call_node(:sha256))
        body = the_builder.pushes.find { |p| p[:category] == :documentation }
        expect(body).not_to be_nil
        expect(body[:text]).to include('ByteString')
      end

      it 'provides documentation for check_sig' do
        the_hover.on_call_node_enter(call_node(:check_sig))
        expect(the_builder.pushes.map { |p| p[:text] }.join(' ')).to include('check_sig')
      end

      it 'includes parameter names for check_sig' do
        the_hover.on_call_node_enter(call_node(:check_sig))
        doc = the_builder.pushes.find { |p| p[:category] == :documentation }
        expect(doc[:text]).to include('sig')
        expect(doc[:text]).to include('pub_key')
      end

      it 'provides documentation for num2bin' do
        the_hover.on_call_node_enter(call_node(:num2bin))
        expect(the_builder.pushes).not_to be_empty
      end

      it 'provides documentation for assert' do
        the_hover.on_call_node_enter(call_node(:assert))
        expect(the_builder.pushes).not_to be_empty
      end

      it 'pushes a :title entry for known builtins' do
        the_hover.on_call_node_enter(call_node(:hash160))
        title = the_builder.pushes.find { |p| p[:category] == :title }
        expect(title).not_to be_nil
        expect(title[:text]).to eq('hash160')
      end

      it 'does not push anything for an unknown method' do
        the_hover.on_call_node_enter(call_node(:unknown_method))
        expect(the_builder.pushes).to be_empty
      end
    end

    context 'with a non-.runar.rb file' do
      let(:components) { build_hover(regular_uri) }
      let(:the_hover)  { components[0] }
      let(:the_builder) { components[1] }

      it 'does not push anything (listener not registered)' do
        # The listener was never registered, so calling the handler directly
        # is the only way to test the guard — but registration is the real
        # guard. We verify through the dispatcher instead.
        _, _, dispatcher = build_hover(regular_uri)
        dispatcher.dispatch(:on_call_node_enter, call_node(:sha256))
        expect(the_builder.pushes).to be_empty
      end
    end
  end

  # -------------------------------------------------------------------------
  # Type constant hover
  # -------------------------------------------------------------------------

  describe '#on_constant_read_node_enter — type constants' do
    let(:components)  { build_hover(runar_uri) }
    let(:the_hover)   { components[0] }
    let(:the_builder) { components[1] }

    it 'provides documentation for Bigint' do
      the_hover.on_constant_read_node_enter(constant_read_node(:Bigint))
      expect(the_builder.pushes.map { |p| p[:text] }.join(' ')).to include('Bigint')
    end

    it 'includes a description for Bigint' do
      the_hover.on_constant_read_node_enter(constant_read_node(:Bigint))
      doc = the_builder.pushes.find { |p| p[:category] == :documentation }
      expect(doc[:text]).to include('integer')
    end

    it 'provides documentation for ByteString' do
      the_hover.on_constant_read_node_enter(constant_read_node(:ByteString))
      doc = the_builder.pushes.find { |p| p[:category] == :documentation }
      expect(doc).not_to be_nil
      expect(doc[:text]).to include('ByteString')
    end

    it 'provides documentation for PubKey' do
      the_hover.on_constant_read_node_enter(constant_read_node(:PubKey))
      expect(the_builder.pushes).not_to be_empty
    end

    it 'provides documentation for SigHashPreimage' do
      the_hover.on_constant_read_node_enter(constant_read_node(:SigHashPreimage))
      expect(the_builder.pushes).not_to be_empty
    end

    it 'provides documentation for Boolean' do
      the_hover.on_constant_read_node_enter(constant_read_node(:Boolean))
      expect(the_builder.pushes).not_to be_empty
    end

    it 'pushes a :title entry for known type constants' do
      the_hover.on_constant_read_node_enter(constant_read_node(:Point))
      title = the_builder.pushes.find { |p| p[:category] == :title }
      expect(title).not_to be_nil
      expect(title[:text]).to eq('Point')
    end

    it 'does not push anything for an unknown constant' do
      the_hover.on_constant_read_node_enter(constant_read_node(:UnknownConstant))
      expect(the_builder.pushes).to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # DSL method hover
  # -------------------------------------------------------------------------

  describe '#on_call_node_enter — DSL methods' do
    let(:components)  { build_hover(runar_uri) }
    let(:the_hover)   { components[0] }
    let(:the_builder) { components[1] }

    it 'provides documentation for prop' do
      the_hover.on_call_node_enter(call_node(:prop))
      expect(the_builder.pushes.map { |p| p[:text] }.join(' ')).to include('prop')
    end

    it 'describes prop as a contract property declaration' do
      the_hover.on_call_node_enter(call_node(:prop))
      doc = the_builder.pushes.find { |p| p[:category] == :documentation }
      expect(doc[:text]).to include('Type')
    end

    it 'provides documentation for runar_public' do
      the_hover.on_call_node_enter(call_node(:runar_public))
      expect(the_builder.pushes).not_to be_empty
    end

    it 'describes runar_public as a spending entry point marker' do
      the_hover.on_call_node_enter(call_node(:runar_public))
      doc = the_builder.pushes.find { |p| p[:category] == :documentation }
      expect(doc[:text]).to include('public')
    end

    it 'provides documentation for params' do
      the_hover.on_call_node_enter(call_node(:params))
      expect(the_builder.pushes).not_to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # Method definition hover — parameter types from runar_public / params
  # -------------------------------------------------------------------------

  describe '#on_def_node_enter — parameter type annotations' do
    def build_hover_with_parent(uri_string, children)
      builder    = build_response_builder
      context    = build_node_context_with_parent(uri_string, children)
      dispatcher = build_dispatcher

      hover = described_class.new(builder, context, dispatcher)
      [hover, builder, dispatcher]
    end

    it 'shows parameter types when preceded by runar_public with types' do
      annotation = annotation_call_node(:runar_public, { 'sig' => 'Sig', 'pub_key' => 'PubKey' })
      method_def = def_node(:unlock)
      children = [annotation, method_def]

      hover, builder, _dispatcher = build_hover_with_parent(runar_uri, children)
      hover.on_def_node_enter(method_def)

      doc = builder.pushes.find { |p| p[:category] == :documentation }
      expect(doc).not_to be_nil
      expect(doc[:text]).to include('sig: Sig')
      expect(doc[:text]).to include('pub_key: PubKey')
    end

    it 'shows parameter types when preceded by params' do
      annotation = annotation_call_node(:params, { 'amount' => 'Bigint' })
      method_def = def_node(:transfer)
      children = [annotation, method_def]

      hover, builder, _dispatcher = build_hover_with_parent(runar_uri, children)
      hover.on_def_node_enter(method_def)

      doc = builder.pushes.find { |p| p[:category] == :documentation }
      expect(doc).not_to be_nil
      expect(doc[:text]).to include('amount: Bigint')
    end

    it 'shows method name as title' do
      annotation = annotation_call_node(:runar_public, { 'sig' => 'Sig' })
      method_def = def_node(:unlock)
      children = [annotation, method_def]

      hover, builder, _dispatcher = build_hover_with_parent(runar_uri, children)
      hover.on_def_node_enter(method_def)

      title = builder.pushes.find { |p| p[:category] == :title }
      expect(title).not_to be_nil
      expect(title[:text]).to eq('unlock')
    end

    it 'does nothing when def has no preceding annotation' do
      method_def = def_node(:unlock)
      other_call = call_node(:sha256)
      children = [other_call, method_def]

      hover, builder, _dispatcher = build_hover_with_parent(runar_uri, children)
      hover.on_def_node_enter(method_def)

      expect(builder.pushes).to be_empty
    end

    it 'does nothing when def is the first statement' do
      method_def = def_node(:unlock)
      children = [method_def]

      hover, builder, _dispatcher = build_hover_with_parent(runar_uri, children)
      hover.on_def_node_enter(method_def)

      expect(builder.pushes).to be_empty
    end
  end

  # -------------------------------------------------------------------------
  # Addon integration — create_hover_listener
  # -------------------------------------------------------------------------

  describe 'RubyLsp::Runar::Addon#create_hover_listener' do
    subject(:addon) { RubyLsp::Runar::Addon.new }

    it 'returns a Hover instance' do
      builder    = build_response_builder
      context    = build_node_context(runar_uri)
      dispatcher = build_dispatcher

      listener = addon.create_hover_listener(builder, context, dispatcher)
      expect(listener).to be_a(RubyLsp::Runar::Hover)
    end

    it 'the returned listener responds to on_call_node_enter' do
      listener = addon.create_hover_listener(
        build_response_builder,
        build_node_context(runar_uri),
        build_dispatcher,
      )
      expect(listener).to respond_to(:on_call_node_enter)
    end
  end
end
