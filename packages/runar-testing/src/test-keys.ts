/**
 * Pre-generated deterministic test keys for use across all test suites.
 *
 * All derived values (public key, pubkey hash, address, WIF) were generated
 * with @bsv/sdk in Node.js and are known-good. Use these instead of
 * PrivateKey.fromRandom() in tests for full reproducibility.
 */

export interface TestKey {
  name: string;
  privKey: string;
  pubKey: string;
  pubKeyHash: string;
  address: string;
  wif: string;
}

export const TEST_KEYS: TestKey[] = [
  {
    name: 'alice',
    privKey: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    pubKey: '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
    pubKeyHash: '9a1c78a507689f6f54b847ad1cef1e614ee23f1e',
    address: '1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV',
    wif: 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
  },
  {
    name: 'bob',
    privKey: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    pubKey: '03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35',
    pubKeyHash: '89b460e4e984ef496ff0b135712f3d9b9fc80482',
    address: '1DZ7fCVer2DBK7XvMQxvFc1hbXLRyunQM4',
    wif: 'L2e2mNWA32XxcdNXyauov5oXp4JBFmXRHWro1JsUa1AZmdFCzqKB',
  },
  {
    name: 'charlie',
    privKey: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    pubKey: '02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae',
    pubKeyHash: '66c1d8577d77be82e3e0e6ac0e14402e3fc67ff3',
    address: '1ANL9AEytMoMwB8uTBRWcK6JhUNs7PDbxC',
    wif: 'L4gZxvfGxeHQYpUcvFwnuaXn8xaBKmvFTm1Z3advYg4xLJ7435BQ',
  },
  {
    name: 'dave',
    privKey: 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe',
    pubKey: '03672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3',
    pubKeyHash: 'd88306005f88e2f485f0b36cbbbc19a4690a6937',
    address: '1Ljov72Bymu55PFahaptQnHxy9yKg5PSQG',
    wif: 'L42Jk1sP2TTKyMjoCTT8ajtDfpXmND7mcWcixcG6D41y3kockVEu',
  },
  {
    name: 'eve',
    privKey: 'abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01',
    pubKey: '02f259306ad65e02f6550fb0c21896cb068ff59189124858664287c7b692d7de4f',
    pubKeyHash: '9fe66d04519c5bb39a5e458d817206e7e0eb80ec',
    address: '1FaUUmdrRT33RRtFbZTRwffysKmq1vxz2W',
    wif: 'L2ygB844zV1cCMD6z7K2bTNAc3i1VPnp6qziDisgBbJCSdJWQETd',
  },
  {
    name: 'frank',
    privKey: '1111111111111111111111111111111111111111111111111111111111111111',
    pubKey: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa',
    pubKeyHash: 'fc7250a211deddc70ee5a2738de5f07817351cef',
    address: '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
    wif: 'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp',
  },
  {
    name: 'grace',
    privKey: '2222222222222222222222222222222222222222222222222222222222222222',
    pubKey: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27',
    pubKeyHash: '531260aa2a199e228c537dfa42c82bea2c7c1f4d',
    address: '18aF6pYXKDSXjXHpidt2G6okdVdBr8zA7z',
    wif: 'KxN4XYdzu6f9j3EMryaMwZvUVLk3y29M4QZ2xwPoFP2zwka1aWxU',
  },
  {
    name: 'heidi',
    privKey: '3333333333333333333333333333333333333333333333333333333333333333',
    pubKey: '023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1',
    pubKeyHash: '3bc28d6d92d9073fb5e3adf481795eaf446bceed',
    address: '16Syw4SugWs4siKbK8cuxJXM2ukh2GKpRi',
    wif: 'KxwEhVPveJrRiwVsu7btTiL3Jhkq2FMzfqTi8qR8wwpStwTcZ1ss',
  },
  {
    name: 'ivan',
    privKey: '4444444444444444444444444444444444444444444444444444444444444444',
    pubKey: '032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991',
    pubKeyHash: 'cc1b07838e387deacd0e5232e1e8b49f4c29e484',
    address: '1KcDEAcEYgV661HME6Sb6h4kQotaCanyHb',
    wif: 'KyWQsS9rPX3hiqmPwFdQyrjc84mc5UaeHGNPJjSUeWbtr8PwT7Ct',
  },
  {
    name: 'judy',
    privKey: '5555555555555555555555555555555555555555555555555555555555555555',
    pubKey: '029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b',
    pubKeyHash: 'e1fae3324e28a4ef5ee01f14dd337ac6c85d1d90',
    address: '1Mbsb8YKL3d38qyEom29NRzLcQc1ajYQNH',
    wif: 'Kz5b3Nun8jEyik2uyPewW19AwRnP8hoHthH4UdTpM5PLoKRAFH9b',
  },
];

// Named exports for convenience
export const ALICE = TEST_KEYS[0]!;
export const BOB = TEST_KEYS[1]!;
export const CHARLIE = TEST_KEYS[2]!;
export const DAVE = TEST_KEYS[3]!;
export const EVE = TEST_KEYS[4]!;
export const FRANK = TEST_KEYS[5]!;
export const GRACE = TEST_KEYS[6]!;
export const HEIDI = TEST_KEYS[7]!;
export const IVAN = TEST_KEYS[8]!;
export const JUDY = TEST_KEYS[9]!;
