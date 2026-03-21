import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'MessageBoard.runar.sol'), 'utf8');
const FILE_NAME = 'MessageBoard.runar.sol';

const OWNER_PK = ALICE.pubKey;
const OWNER_SIG = signTestMessage(ALICE.privKey);

describe('MessageBoard (Solidity)', () => {
  it('starts with initial message', () => {
    const board = TestContract.fromSource(source, { message: '48656c6c6f', owner: OWNER_PK }, FILE_NAME);
    expect(board.state.message).toBe('48656c6c6f');
  });

  it('updates message via post', () => {
    const board = TestContract.fromSource(source, { message: '00', owner: OWNER_PK }, FILE_NAME);
    const result = board.call('post', { newMessage: '48656c6c6f' });
    expect(result.success).toBe(true);
    expect(board.state.message).toBe('48656c6c6f');
  });

  it('tracks state across multiple posts', () => {
    const board = TestContract.fromSource(source, { message: '00', owner: OWNER_PK }, FILE_NAME);
    board.call('post', { newMessage: 'aabb' });
    board.call('post', { newMessage: 'ccdd' });
    expect(board.state.message).toBe('ccdd');
  });

  it('burns successfully with owner signature', () => {
    const board = TestContract.fromSource(source, { message: '00', owner: OWNER_PK }, FILE_NAME);
    const result = board.call('burn', { sig: OWNER_SIG });
    expect(result.success).toBe(true);
  });

  it('preserves readonly owner across posts', () => {
    const board = TestContract.fromSource(source, { message: '00', owner: OWNER_PK }, FILE_NAME);
    board.call('post', { newMessage: 'aabb' });
    expect(board.state.owner).toBe(OWNER_PK);
  });

  it('starts with an empty message', () => {
    const board = TestContract.fromSource(source, { message: '', owner: OWNER_PK }, FILE_NAME);
    expect(board.state.message).toBe('');
  });

  it('posts to a board initialized with empty message', () => {
    const board = TestContract.fromSource(source, { message: '', owner: OWNER_PK }, FILE_NAME);
    const result = board.call('post', { newMessage: '48656c6c6f' });
    expect(result.success).toBe(true);
    expect(board.state.message).toBe('48656c6c6f');
  });
});
