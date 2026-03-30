# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'MessageBoard.runar'

RSpec.describe MessageBoard do
  let(:owner) { mock_pub_key }

  it 'starts with initial message' do
    board = MessageBoard.new('48656c6c6f', owner)
    expect(board.message).to eq('48656c6c6f')
  end

  it 'updates message via post' do
    board = MessageBoard.new('00', owner)
    board.post('48656c6c6f')
    expect(board.message).to eq('48656c6c6f')
  end

  it 'tracks state across multiple posts' do
    board = MessageBoard.new('00', owner)
    board.post('aabb')
    board.post('ccdd')
    expect(board.message).to eq('ccdd')
  end

  it 'burns successfully with owner signature' do
    board = MessageBoard.new('00', owner)
    expect { board.burn(mock_sig) }.not_to raise_error
  end

  it 'preserves readonly owner across posts' do
    board = MessageBoard.new('00', owner)
    board.post('aabb')
    expect(board.owner).to eq(owner)
  end

  it 'starts with an empty message' do
    board = MessageBoard.new('', owner)
    expect(board.message).to eq('')
  end

  it 'posts to a board initialized with empty message' do
    board = MessageBoard.new('', owner)
    board.post('48656c6c6f')
    expect(board.message).to eq('48656c6c6f')
  end
end
