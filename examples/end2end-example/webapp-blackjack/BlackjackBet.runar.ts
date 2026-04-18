import { StatefulSmartContract, assert, PubKey, Sig, ByteString, RabinSig, RabinPubKey, checkSig, verifyRabinSig, num2bin, cat, hash160, hash256, extractOutputHash } from 'runar-lang';

/**
 * BlackjackBet -- a blackjack wager with oracle-attested outcomes.
 *
 * Oracle replay note: The oracle signs `cat(outcomeType, oracleThreshold,
 * nonce)`. The oracleThreshold field binds signatures to this contract's
 * parameters, providing partial domain separation. However, the same signed
 * message structure is used across settleBlackjack, settleWin, and
 * settleLoss -- only the outcomeType value differentiates them. For
 * production contracts, consider including the contract's UTXO outpoint or
 * locking script hash in the oracle message to prevent cross-contract replay.
 */
class BlackjackBet extends StatefulSmartContract {
  readonly playerPubKey: PubKey;
  readonly housePubKey: PubKey;
  readonly oraclePubKey: RabinPubKey;
  readonly oracleThreshold: bigint;
  readonly betAmount: bigint;
  readonly p2pkhPrefix: ByteString;
  readonly p2pkhSuffix: ByteString;

  constructor(playerPubKey: PubKey, housePubKey: PubKey, oraclePubKey: RabinPubKey, oracleThreshold: bigint, betAmount: bigint, p2pkhPrefix: ByteString, p2pkhSuffix: ByteString) {
    super(playerPubKey, housePubKey, oraclePubKey, oracleThreshold, betAmount, p2pkhPrefix, p2pkhSuffix);
    this.playerPubKey = playerPubKey;
    this.housePubKey = housePubKey;
    this.oraclePubKey = oraclePubKey;
    this.oracleThreshold = oracleThreshold;
    this.betAmount = betAmount;
    this.p2pkhPrefix = p2pkhPrefix;
    this.p2pkhSuffix = p2pkhSuffix;
  }

  public settleBlackjack(outcomeType: bigint, nonce: bigint, rabinSig: RabinSig, padding: ByteString, playerSig: Sig) {
    const msg = cat(cat(num2bin(outcomeType, 8n), num2bin(this.oracleThreshold, 8n)), num2bin(nonce, 8n));
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(outcomeType == 2n);
    const totalSats = this.betAmount + this.betAmount * 3n / 2n;
    const output = cat(cat(num2bin(totalSats, 8n), this.p2pkhPrefix), cat(hash160(this.playerPubKey), this.p2pkhSuffix));
    const expectedHash = hash256(output);
    const actualHash = extractOutputHash(this.txPreimage);
    assert(expectedHash == actualHash);
    assert(checkSig(playerSig, this.playerPubKey));
  }

  public settleWin(outcomeType: bigint, nonce: bigint, rabinSig: RabinSig, padding: ByteString, playerSig: Sig) {
    const msg = cat(cat(num2bin(outcomeType, 8n), num2bin(this.oracleThreshold, 8n)), num2bin(nonce, 8n));
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(outcomeType == 1n);
    const playerPayout = this.betAmount * 2n;
    const houseChange = this.betAmount * 3n / 2n - this.betAmount;
    const out1 = cat(cat(num2bin(playerPayout, 8n), this.p2pkhPrefix), cat(hash160(this.playerPubKey), this.p2pkhSuffix));
    const out2 = cat(cat(num2bin(houseChange, 8n), this.p2pkhPrefix), cat(hash160(this.housePubKey), this.p2pkhSuffix));
    const expectedHash = hash256(cat(out1, out2));
    const actualHash = extractOutputHash(this.txPreimage);
    assert(expectedHash == actualHash);
    assert(checkSig(playerSig, this.playerPubKey));
  }

  public settleLoss(outcomeType: bigint, nonce: bigint, rabinSig: RabinSig, padding: ByteString, houseSig: Sig) {
    const msg = cat(cat(num2bin(outcomeType, 8n), num2bin(this.oracleThreshold, 8n)), num2bin(nonce, 8n));
    assert(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));
    assert(outcomeType == 0n);
    const totalSats = this.betAmount + this.betAmount * 3n / 2n;
    const output = cat(cat(num2bin(totalSats, 8n), this.p2pkhPrefix), cat(hash160(this.housePubKey), this.p2pkhSuffix));
    const expectedHash = hash256(output);
    const actualHash = extractOutputHash(this.txPreimage);
    assert(expectedHash == actualHash);
    assert(checkSig(houseSig, this.housePubKey));
  }

  public cancel(playerSig: Sig, houseSig: Sig) {
    const out1 = cat(cat(num2bin(this.betAmount, 8n), this.p2pkhPrefix), cat(hash160(this.playerPubKey), this.p2pkhSuffix));
    const out2 = cat(cat(num2bin(this.betAmount * 3n / 2n, 8n), this.p2pkhPrefix), cat(hash160(this.housePubKey), this.p2pkhSuffix));
    const expectedHash = hash256(cat(out1, out2));
    const actualHash = extractOutputHash(this.txPreimage);
    assert(expectedHash == actualHash);
    assert(checkSig(playerSig, this.playerPubKey));
    assert(checkSig(houseSig, this.housePubKey));
  }
}
