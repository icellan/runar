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
  /** DER-encoded ECDSA signature over TEST_MESSAGE (deterministic via RFC 6979). */
  testSig: string;
}

export const TEST_KEYS: TestKey[] = [
  {
    name: 'alice',
    privKey: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    pubKey: '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
    pubKeyHash: '9a1c78a507689f6f54b847ad1cef1e614ee23f1e',
    address: '1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV',
    wif: 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
    testSig: '3045022100e2aa1265ce57f54b981ffc6a5f3d229e908d7772fceb75a50c8c2d6076313df00220607dbca2f9f695438b49eefea4e445664c740163af8b62b1373f87d50eb64417',
  },
  {
    name: 'bob',
    privKey: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    pubKey: '03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35',
    pubKeyHash: '89b460e4e984ef496ff0b135712f3d9b9fc80482',
    address: '1DZ7fCVer2DBK7XvMQxvFc1hbXLRyunQM4',
    wif: 'L2e2mNWA32XxcdNXyauov5oXp4JBFmXRHWro1JsUa1AZmdFCzqKB',
    testSig: '3044022058329072a0f9e6133d93109502ddea833f043f00b460950683fa80c00ca4d98802200328ff8f8c1da673a489c93ed0b8e83b143afbeb3495ae4aad4714c256984608',
  },
  {
    name: 'charlie',
    privKey: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    pubKey: '02c6b754b20826eb925e052ee2c25285b162b51fdca732bcf67e39d647fb6830ae',
    pubKeyHash: '66c1d8577d77be82e3e0e6ac0e14402e3fc67ff3',
    address: '1ANL9AEytMoMwB8uTBRWcK6JhUNs7PDbxC',
    wif: 'L4gZxvfGxeHQYpUcvFwnuaXn8xaBKmvFTm1Z3advYg4xLJ7435BQ',
    testSig: '3043022100aa67cfa7255b90992a8f5d2bc7e9a38f42b12b3a6c7cca7cb654a171e3aefd85021e277740c4409c641cfb47370f510b3ecfff752488a855aacfc9913e66d038',
  },
  {
    name: 'dave',
    privKey: 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe',
    pubKey: '03672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3',
    pubKeyHash: 'd88306005f88e2f485f0b36cbbbc19a4690a6937',
    address: '1Ljov72Bymu55PFahaptQnHxy9yKg5PSQG',
    wif: 'L42Jk1sP2TTKyMjoCTT8ajtDfpXmND7mcWcixcG6D41y3kockVEu',
    testSig: '30440220127bee35050df26cfa366e97e9c02ec33ebff69a204c1dc25aefc8b31397619802201a2157c935108716ec41d53b7137238083a331f57e0f8e34953f2a5f54acb7c9',
  },
  {
    name: 'eve',
    privKey: 'abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01',
    pubKey: '02f259306ad65e02f6550fb0c21896cb068ff59189124858664287c7b692d7de4f',
    pubKeyHash: '9fe66d04519c5bb39a5e458d817206e7e0eb80ec',
    address: '1FaUUmdrRT33RRtFbZTRwffysKmq1vxz2W',
    wif: 'L2ygB844zV1cCMD6z7K2bTNAc3i1VPnp6qziDisgBbJCSdJWQETd',
    testSig: '3045022100cfcc9cd4dca3905979c2b2b0c9646459a8cfb8eeec4b476c06ff6e7333a0dbd2022029443a9aafa6dc08231043f06940cfcf045c6e3783314ccac252d4333fb7a114',
  },
  {
    name: 'frank',
    privKey: '1111111111111111111111111111111111111111111111111111111111111111',
    pubKey: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa',
    pubKeyHash: 'fc7250a211deddc70ee5a2738de5f07817351cef',
    address: '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
    wif: 'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp',
    testSig: '3044022053fff242b1c221d510fc062ede923778020171f807a89b582953c15db0bb6f8e02207f49fd920e6b947d09a394072b7804900fa81a6d46d86066e217b4ffc3691b3d',
  },
  {
    name: 'grace',
    privKey: '2222222222222222222222222222222222222222222222222222222222222222',
    pubKey: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27',
    pubKeyHash: '531260aa2a199e228c537dfa42c82bea2c7c1f4d',
    address: '18aF6pYXKDSXjXHpidt2G6okdVdBr8zA7z',
    wif: 'KxN4XYdzu6f9j3EMryaMwZvUVLk3y29M4QZ2xwPoFP2zwka1aWxU',
    testSig: '3045022100f764889b01cb498c05c4f5c2718bb0cca0c6cd00299ea73a9fe7d01900fbff8202204738757bbf407e42cd292375387e38fa53c983a2c75d5eeeaf0512e44b4e9a91',
  },
  {
    name: 'heidi',
    privKey: '3333333333333333333333333333333333333333333333333333333333333333',
    pubKey: '023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1',
    pubKeyHash: '3bc28d6d92d9073fb5e3adf481795eaf446bceed',
    address: '16Syw4SugWs4siKbK8cuxJXM2ukh2GKpRi',
    wif: 'KxwEhVPveJrRiwVsu7btTiL3Jhkq2FMzfqTi8qR8wwpStwTcZ1ss',
    testSig: '3045022100f83d7c0ed0f48f680f40a4b38c9872bb14cb2396af19b4b2713a0bf99b17457702205b1f04cac7da387a46e7beb958fa8b523a803ace06148a0d7557960ff2388790',
  },
  {
    name: 'ivan',
    privKey: '4444444444444444444444444444444444444444444444444444444444444444',
    pubKey: '032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991',
    pubKeyHash: 'cc1b07838e387deacd0e5232e1e8b49f4c29e484',
    address: '1KcDEAcEYgV661HME6Sb6h4kQotaCanyHb',
    wif: 'KyWQsS9rPX3hiqmPwFdQyrjc84mc5UaeHGNPJjSUeWbtr8PwT7Ct',
    testSig: '3045022100d60c57d9501b3fecd50d35be73176eb3dad7506f37e0671d9018bd1de71dd314022060b010c949554d8301e09ea42700bffedb2f08f75336ce3aa0f66f955ece6e02',
  },
  {
    name: 'judy',
    privKey: '5555555555555555555555555555555555555555555555555555555555555555',
    pubKey: '029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b',
    pubKeyHash: 'e1fae3324e28a4ef5ee01f14dd337ac6c85d1d90',
    address: '1Mbsb8YKL3d38qyEom29NRzLcQc1ajYQNH',
    wif: 'Kz5b3Nun8jEyik2uyPewW19AwRnP8hoHthH4UdTpM5PLoKRAFH9b',
    testSig: '304402207fb1e45b48dd8ffeff9678ecf394d912fd0446bb85532159f44e6b26b701e0c902205a60cb2b2fab76922c52b115843f6843b0a1715f832629ea0d126f9dc663c0f3',
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
