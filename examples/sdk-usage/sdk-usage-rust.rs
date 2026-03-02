//! Rúnar Rust SDK Usage Examples
//!
//! Comprehensive examples for compiling, deploying, and spending all 8 Rúnar
//! example contracts using the Rust compiler as a library.
//!
//! Contracts: P2PKH, Escrow, Counter, FungibleToken, NFT, Auction,
//!            OraclePriceFeed, CovenantVault
//!
//! Prerequisites (Cargo.toml):
//!   runar-compiler-rust = { path = "compilers/rust" }
//!   sha2 = "0.10"
//!
//! Run: cargo run --example sdk-usage-rust

use std::path::Path;
use runar_compiler_rust::artifact::RunarArtifact;
use runar_compiler_rust::{compile_from_source, compile_from_source_str};

// ============================================================================
// Helper utilities
// ============================================================================

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}

/// Encode integer as Bitcoin Script number (little-endian sign-magnitude).
fn encode_script_number(n: i64) -> Vec<u8> {
    if n == 0 { return vec![]; }
    let negative = n < 0;
    let mut abs = if negative { -(n as i128) } else { n as i128 } as u64;
    let mut result = Vec::new();
    while abs > 0 { result.push((abs & 0xff) as u8); abs >>= 8; }
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.len() - 1;
        result[last] |= 0x80;
    }
    result
}

/// CompactSize varint for Bitcoin transaction serialization.
fn encode_varint(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => { let mut v = vec![0xfd]; v.extend(&(n as u16).to_le_bytes()); v }
        0x10000..=0xffff_ffff => { let mut v = vec![0xfe]; v.extend(&(n as u32).to_le_bytes()); v }
        _ => { let mut v = vec![0xff]; v.extend(&n.to_le_bytes()); v }
    }
}

/// Push data onto Bitcoin Script stack with minimal encoding.
fn script_push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut r = Vec::new();
    match len {
        0 => { r.push(0x00); }
        1..=75 => { r.push(len as u8); r.extend(data); }
        76..=255 => { r.push(0x4c); r.push(len as u8); r.extend(data); }
        _ => { r.push(0x4d); r.extend(&(len as u16).to_le_bytes()); r.extend(data); }
    }
    r
}

/// Push a script number using OP_0, OP_1NEGATE, OP_1..OP_16 where possible.
fn script_push_int(n: i64) -> Vec<u8> {
    match n {
        0 => vec![0x00],
        -1 => vec![0x4f],
        1..=16 => vec![0x50 + n as u8],
        _ => script_push_data(&encode_script_number(n)),
    }
}

/// SHA-256 double hash (hash256).
fn hash256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}

/// Placeholder HASH160 (production: use ripemd crate for ripemd160(sha256(data))).
fn hash160_stub(data: &[u8]) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 20];
    out.copy_from_slice(&Sha256::digest(data)[..20]);
    out
}

fn separator(title: &str) {
    println!("\n{}\n  {}\n{}\n", "=".repeat(72), title, "=".repeat(72));
}

/// Print artifact summary: name, script, ABI, state fields.
fn print_summary(a: &RunarArtifact) {
    println!("Contract: {}  |  Script: {} bytes  |  ASM: {}", a.contract_name, a.script.len()/2, a.asm);
    for p in &a.abi.constructor.params { println!("  ctor param: {} : {}", p.name, p.param_type); }
    for m in &a.abi.methods {
        let ps: Vec<String> = m.params.iter().map(|p| format!("{}:{}", p.name, p.param_type)).collect();
        println!("  method: {}({})  public={}", m.name, ps.join(", "), m.is_public);
    }
    for sf in &a.state_fields { println!("  state: {} : {} [idx={}]", sf.name, sf.field_type, sf.index); }
}

/// Build a minimal 1-in/1-out raw transaction.
fn build_raw_tx(prev_txid: &[u8; 32], vout: u32, script_sig: &[u8],
                locking: &[u8], sats: u64, locktime: u32) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend(&1u32.to_le_bytes());                        // nVersion
    tx.extend(&encode_varint(1));                           // input count
    tx.extend(prev_txid);                                   // prev txid
    tx.extend(&vout.to_le_bytes());                         // prev vout
    tx.extend(&encode_varint(script_sig.len() as u64));     // scriptSig len
    tx.extend(script_sig);                                  // scriptSig
    tx.extend(&0xffff_ffffu32.to_le_bytes());               // nSequence
    tx.extend(&encode_varint(1));                           // output count
    tx.extend(&sats.to_le_bytes());                         // value
    tx.extend(&encode_varint(locking.len() as u64));        // scriptPubKey len
    tx.extend(locking);                                     // scriptPubKey
    tx.extend(&locktime.to_le_bytes());                     // nLockTime
    tx
}

// ============================================================================
// 1. P2PKH -- Pay to Public Key Hash
// ============================================================================

/// Compile, deploy, and spend a P2PKH contract.
///
/// This is the simplest Rúnar contract: a single-method script that checks
/// hash160(pubKey) == pubKeyHash and verifies an ECDSA signature. It is the
/// Rúnar equivalent of Bitcoin's standard P2PKH output.
///
/// Contract source (P2PKH.runar.ts):
///   constructor(pubKeyHash: Addr)
///   unlock(sig: Sig, pubKey: PubKey)
///     assert(hash160(pubKey) === this.pubKeyHash)
///     assert(checkSig(sig, pubKey))
fn example_p2pkh() -> Result<(), String> {
    separator("1. P2PKH -- Pay to Public Key Hash");

    // Step 1: Compile from source file on disk.
    // compile_from_source runs all 6 passes: parse -> validate -> typecheck
    // -> ANF lower -> stack lower -> emit.
    let artifact = compile_from_source(Path::new("examples/ts/p2pkh/P2PKH.runar.ts"))?;
    print_summary(&artifact);

    // Step 2: Prepare constructor arguments.
    // The pubKeyHash is the HASH160 of the recipient's compressed public key.
    let pubkey = from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let pkh = hash160_stub(&pubkey);
    println!("\nDeploy parameters:");
    println!("  pubKey (33 bytes):     {}", to_hex(&pubkey));
    println!("  pubKeyHash (20 bytes): {}", to_hex(&pkh));

    // Step 3: Build the locking script (scriptPubKey) for the deployment UTXO.
    // Rúnar locking script layout: <constructor_args> <compiled_contract_code>
    // The constructor args are pushed first; the compiled code consumes them
    // via load_prop instructions that reference stack positions.
    let mut lock = Vec::new();
    lock.extend(&script_push_data(&pkh));          // push pubKeyHash (20 bytes)
    lock.extend(&from_hex(&artifact.script));       // compiled contract bytecode
    println!("\nLocking script: {} bytes", lock.len());
    println!("  = [push 20-byte hash] + [{}  bytes compiled code]", artifact.script.len() / 2);

    // Step 4: Build a deployment transaction.
    // This is a standard Bitcoin TX that creates a UTXO locked by our Rúnar script.
    let funding_txid = [0xaa; 32]; // placeholder: txid of the funding input
    let deploy_tx = build_raw_tx(&funding_txid, 0, &[], &lock, 10_000, 0);
    println!("\nDeploy TX: {} bytes  |  Locking 10,000 satoshis", deploy_tx.len());

    // Step 5: Build the unlocking (spending) transaction.
    // scriptSig = <sig> <pubKey>
    // For single-method contracts, no method dispatch selector is needed.
    // The Bitcoin Script VM concatenates scriptSig + scriptPubKey and runs them.
    // Stack before execution: bottom -> [sig, pubKey] -> top
    let fake_sig = vec![0x30; 72]; // DER-encoded ECDSA signature placeholder
    let mut ssig = Vec::new();
    ssig.extend(&script_push_data(&fake_sig));    // push <sig>
    ssig.extend(&script_push_data(&pubkey));      // push <pubKey>
    println!("\nscriptSig: {} bytes", ssig.len());
    println!("  = [push 72-byte sig] + [push 33-byte pubkey]");

    let deploy_txid = hash256(&deploy_tx);
    let p2pkh_out = [0x76, 0xa9, 0x14, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x88, 0xac];
    let spend_tx = build_raw_tx(&deploy_txid, 0, &ssig, &p2pkh_out, 9_500, 0);
    println!("Spend TX:  {} bytes  |  Sending 9,500 sats (500 fee)", spend_tx.len());
    Ok(())
}

// ============================================================================
// 2. Escrow -- 3-party multi-method
// ============================================================================

/// Compile and demonstrate a 3-party Escrow with 4 spending methods.
///
/// Multi-method dispatch: Rúnar compiles N methods into a nested OP_IF/OP_ELSE
/// tree. The spender pushes method selector values (0 or 1) in the scriptSig
/// to navigate to the desired branch.
///
/// Contract source (Escrow.runar.ts):
///   constructor(buyer: PubKey, seller: PubKey, arbiter: PubKey)
///   releaseBySeller(sig)  -- seller releases funds to buyer
///   releaseByArbiter(sig) -- arbiter releases funds to buyer
///   refundToBuyer(sig)    -- buyer reclaims their deposit
///   refundByArbiter(sig)  -- arbiter authorizes refund to buyer
fn example_escrow() -> Result<(), String> {
    separator("2. Escrow -- 3-Party Multi-Method");
    let artifact = compile_from_source(Path::new("examples/ts/escrow/Escrow.runar.ts"))?;
    print_summary(&artifact);

    // Three parties, each identified by a compressed public key (33 bytes).
    let buyer   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let seller  = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let arbiter = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    // Locking script: <buyer> <seller> <arbiter> <compiled_code>
    let mut lock = Vec::new();
    for pk in [buyer, seller, arbiter] {
        lock.extend(&script_push_data(&from_hex(pk)));
    }
    lock.extend(&from_hex(&artifact.script));
    println!("\nDeploy locking script: {} bytes", lock.len());

    // Multi-method dispatch tree (generated by the Rúnar compiler):
    //
    //   <selector_N> OP_IF
    //     [method 0 body]
    //   OP_ELSE
    //     <selector_N-1> OP_IF
    //       [method 1 body]
    //     OP_ELSE
    //       <selector_N-2> OP_IF
    //         [method 2 body]
    //       OP_ELSE
    //         [method 3 body]
    //       OP_ENDIF
    //     OP_ENDIF
    //   OP_ENDIF
    //
    // The spender pushes selector values onto the stack (in scriptSig) so that
    // the correct branch executes. Each selector is 0 (false) or 1 (true).

    let sig_placeholder = script_push_data(&vec![0x30; 72]);
    let paths = [
        ("releaseBySeller",  vec![1],        "outer IF"),
        ("releaseByArbiter", vec![0, 1],     "outer ELSE -> inner IF"),
        ("refundToBuyer",    vec![0, 0, 1],  "ELSE -> ELSE -> IF"),
        ("refundByArbiter",  vec![0, 0, 0],  "ELSE -> ELSE -> ELSE"),
    ];
    println!("\nMethod dispatch paths:");
    for (name, selectors, path_desc) in &paths {
        let mut ssig = sig_placeholder.clone();
        for &s in selectors { ssig.extend(&script_push_int(s)); }
        println!("  {} => selectors {:?} ({})  |  scriptSig: {} bytes",
                 name, selectors, path_desc, ssig.len());
    }
    Ok(())
}

// ============================================================================
// 3. Counter -- Stateful with OP_PUSH_TX
// ============================================================================

/// Stateful counter: increment/decrement with BIP-143 sighash preimage.
///
/// OP_PUSH_TX (BIP-143 sighash preimage):
///   [4] nVersion  [32] hashPrevouts  [32] hashSequence  [32] outpoint
///   [4] nSequence  [var] scriptCode  [8] value  [32] hashOutputs
///   [4] nLockTime  [4] sighashType (0x41 = ALL|FORKID)
///
/// Signature with privkey=1, pubkey=G (generator):
///   r = Gx = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
///   s = (sighash + r) mod n  (curve order n = FFFFFFFFFFFFFFFFFFFFFFFFFFF...364141)
///   OP_CHECKSIG verifies: s*G == z*G + r*P, and since P=G, k=1 it checks out.
///   Reference: https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
fn example_counter() -> Result<(), String> {
    separator("3. Counter -- Stateful with OP_PUSH_TX");
    let artifact = compile_from_source(Path::new("examples/ts/stateful-counter/Counter.runar.ts"))?;
    print_summary(&artifact);
    assert!(!artifact.state_fields.is_empty(), "Counter must have state fields");

    // Deploy with count=0
    let mut lock = Vec::new();
    lock.extend(&script_push_int(0));  // state: count = 0
    lock.extend(&from_hex(&artifact.script));
    println!("\nDeploy: count=0, locking script: {} bytes", lock.len());

    // After increment: count=1 -- new locking script for the output
    let mut new_lock = Vec::new();
    new_lock.extend(&script_push_int(1));
    new_lock.extend(&from_hex(&artifact.script));
    println!("After increment: count=1, new locking: {} bytes", new_lock.len());

    // hashOutputs must match hash256(new locking script) for state validation
    let mut output_ser = Vec::new();
    output_ser.extend(&9500u64.to_le_bytes());
    output_ser.extend(&encode_varint(new_lock.len() as u64));
    output_ser.extend(&new_lock);
    println!("hashOutputs:        {}", to_hex(&hash256(&output_ser)));
    println!("hash256(stateScrpt):{}", to_hex(&hash256(&new_lock)));
    println!("These MUST match for extractOutputHash == hash256(getStateScript())");

    // --- Construct a BIP-143 sighash preimage (demonstration) ---
    // In production you would compute this from the actual transaction fields.
    // Here we show the structure with placeholder values.
    let mut preimage = Vec::new();
    preimage.extend(&1u32.to_le_bytes());           // nVersion = 1
    preimage.extend(&[0u8; 32]);                     // hashPrevouts (placeholder)
    preimage.extend(&[0u8; 32]);                     // hashSequence (placeholder)
    preimage.extend(&[0u8; 32]);                     // outpoint txid
    preimage.extend(&0u32.to_le_bytes());            // outpoint vout
    // scriptCode: varint length + the locking script being spent
    preimage.extend(&encode_varint(lock.len() as u64));
    preimage.extend(&lock);
    preimage.extend(&10000u64.to_le_bytes());        // value (satoshis in UTXO)
    preimage.extend(&0xffff_ffffu32.to_le_bytes());  // nSequence
    preimage.extend(&hash256(&output_ser));           // hashOutputs
    preimage.extend(&0u32.to_le_bytes());            // nLockTime
    preimage.extend(&0x41u32.to_le_bytes());         // sighashType = ALL|FORKID
    println!("\nBIP-143 preimage: {} bytes (constructed)", preimage.len());

    println!("\nscriptSig: <txPreimage> <method_selector>");
    println!("  increment: selector=1 | decrement: selector=0");

    // State transition chain: each TX spends the previous and creates a new
    // UTXO with the updated count baked into the locking script.
    println!("\nState chain:");
    println!("  TX0: deploy   -> count=0");
    println!("  TX1: increment -> count=1 (output must contain count=1 in locking script)");
    println!("  TX2: increment -> count=2 (output must contain count=2)");
    println!("  TX3: decrement -> count=1 (output must contain count=1)");
    Ok(())
}

// ============================================================================
// 4. FungibleToken -- Stateful token transfer
// ============================================================================

/// Stateful fungible token: transfer ownership with OP_PUSH_TX.
///
/// The `owner` property is mutable (stateful) -- it changes on each transfer.
/// The `supply` property is readonly (immutable) -- fixed at deploy time.
/// This distinction is declared in the Rúnar source:
///   owner: PubKey;          // no readonly = mutable state
///   readonly supply: bigint; // readonly = immutable
///
/// The compiler tracks state fields in the artifact's `state_fields` array,
/// which tells the SDK which parts of the locking script need updating.
fn example_fungible_token() -> Result<(), String> {
    separator("4. FungibleToken -- Stateful Token Transfer");
    let artifact = compile_from_source(Path::new("examples/ts/token-ft/FungibleTokenExample.runar.ts"))?;
    print_summary(&artifact);

    let owner = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let supply: i64 = 1_000_000;
    let new_owner = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    // Deploy: locking script = <owner> <supply> <compiled_code>
    let mut lock = Vec::new();
    lock.extend(&script_push_data(&from_hex(owner)));   // state: current owner
    lock.extend(&script_push_int(supply));               // readonly: total supply
    lock.extend(&from_hex(&artifact.script));            // contract bytecode
    println!("\nDeploy: owner={}..., supply={}, locking: {} bytes", &owner[..16], supply, lock.len());

    // After transfer: only owner changes; supply and code stay the same.
    let mut new_lock = Vec::new();
    new_lock.extend(&script_push_data(&from_hex(new_owner))); // updated owner
    new_lock.extend(&script_push_int(supply));                  // supply unchanged
    new_lock.extend(&from_hex(&artifact.script));               // same code
    println!("Transfer: new_owner={}..., locking: {} bytes", &new_owner[..16], new_lock.len());

    println!("\nscriptSig: <sig> <newOwner> <txPreimage>");
    println!("  Script execution:");
    println!("    1. checkSig(sig, this.owner)  -- only current owner can transfer");
    println!("    2. checkPreimage(txPreimage)  -- OP_PUSH_TX validates preimage");
    println!("    3. this.owner = newOwner       -- update state in memory");
    println!("    4. hash256(getStateScript()) == extractOutputHash(txPreimage)");
    println!("       ^-- enforces that the spending TX output contains the new state");
    println!("  supply remains {} across all transfers (immutable)", supply);
    Ok(())
}

// ============================================================================
// 5. NFT -- Non-Fungible Token (transfer + burn)
// ============================================================================

/// NFT with two methods: transfer (stateful) and burn (terminal).
///
/// Key difference between transfer and burn:
///   - transfer: stateful -- uses OP_PUSH_TX to enforce state continuation.
///     The spending TX must create a new output with the updated owner.
///   - burn: terminal -- no state continuation. The UTXO is consumed and
///     no new contract output is required. The NFT ceases to exist.
fn example_nft() -> Result<(), String> {
    separator("5. NFT -- Non-Fungible Token");
    let artifact = compile_from_source(Path::new("examples/ts/token-nft/NFTExample.runar.ts"))?;
    print_summary(&artifact);

    let owner = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let token_id = "4e46542d30303031";       // "NFT-0001" as hex bytes
    let metadata = "697066733a2f2f516d5a6b";  // "ipfs://QmZk" as hex bytes

    // Deploy: <owner> <tokenId> <metadata> <compiled_code>
    // owner is mutable (state); tokenId and metadata are readonly (immutable)
    let mut lock = Vec::new();
    lock.extend(&script_push_data(&from_hex(owner)));      // state: owner
    lock.extend(&script_push_data(&from_hex(token_id)));   // readonly: tokenId
    lock.extend(&script_push_data(&from_hex(metadata)));   // readonly: metadata
    lock.extend(&from_hex(&artifact.script));
    println!("\nDeploy: tokenId=\"NFT-0001\", metadata=\"ipfs://QmZk\"");
    println!("  Locking script: {} bytes", lock.len());

    // Transfer (multi-method contract, so needs dispatch selector)
    let new_owner = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    println!("\n--- transfer (stateful, method selector=1) ---");
    println!("  scriptSig: <sig> <newOwner> <txPreimage> <selector=1>");
    println!("  owner changes to {}...", &new_owner[..16]);
    println!("  tokenId and metadata remain identical (readonly fields)");

    // New locking script after transfer
    let mut new_lock = Vec::new();
    new_lock.extend(&script_push_data(&from_hex(new_owner)));
    new_lock.extend(&script_push_data(&from_hex(token_id)));
    new_lock.extend(&script_push_data(&from_hex(metadata)));
    new_lock.extend(&from_hex(&artifact.script));
    println!("  New locking script: {} bytes", new_lock.len());

    println!("\n--- burn (terminal, method selector=0) ---");
    println!("  scriptSig: <sig> <selector=0>");
    println!("  No txPreimage needed -- no output state to validate.");
    println!("  The UTXO is consumed; the NFT is permanently destroyed on-chain.");
    Ok(())
}

// ============================================================================
// 6. Auction -- Stateful with locktime enforcement
// ============================================================================

/// Stateful auction with locktime enforcement via BIP-143 preimage.
///
/// The nLockTime field is extracted from the sighash preimage using
/// extractLocktime(). This allows the script to enforce time-based rules:
///   - Bids are only accepted BEFORE the deadline (locktime < deadline)
///   - Close is only allowed AFTER the deadline (locktime >= deadline)
///
/// State fields: highestBidder (PubKey), highestBid (bigint) -- both mutable.
/// Readonly fields: auctioneer (PubKey), deadline (bigint).
fn example_auction() -> Result<(), String> {
    separator("6. Auction -- Stateful with Locktime");
    let artifact = compile_from_source(Path::new("examples/ts/auction/Auction.runar.ts"))?;
    print_summary(&artifact);

    let auctioneer = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let deadline: i64 = 800_000;

    // Deploy: <auctioneer> <highestBidder=null> <highestBid=0> <deadline> <code>
    let mut lock = Vec::new();
    lock.extend(&script_push_data(&from_hex(auctioneer)));
    lock.extend(&script_push_data(&[0u8; 33]));  // null initial bidder
    lock.extend(&script_push_int(0));              // initial bid = 0
    lock.extend(&script_push_int(deadline));
    lock.extend(&from_hex(&artifact.script));
    println!("\nDeploy: deadline=block {}, locking: {} bytes", deadline, lock.len());

    println!("\n--- bid (method 0, stateful) ---");
    println!("  scriptSig: <bidder> <bidAmount> <txPreimage> <selector>");
    println!("  Checks: bidAmount > highestBid, extractLocktime(preimage) < {}", deadline);
    println!("  State update: highestBidder = bidder, highestBid = bidAmount");

    let bidder = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let mut new_lock = Vec::new();
    new_lock.extend(&script_push_data(&from_hex(auctioneer)));
    new_lock.extend(&script_push_data(&from_hex(bidder)));
    new_lock.extend(&script_push_int(50_000));
    new_lock.extend(&script_push_int(deadline));
    new_lock.extend(&from_hex(&artifact.script));
    println!("  After bid: highestBid=50000, new locking: {} bytes", new_lock.len());

    println!("\n--- close (method 1, terminal) ---");
    println!("  scriptSig: <sig> <txPreimage> <selector>");
    println!("  Checks: checkSig(auctioneer), extractLocktime(preimage) >= {}", deadline);
    println!("  No state continuation -- auction finalized.");
    Ok(())
}

// ============================================================================
// 7. OraclePriceFeed -- Rabin signature oracle
// ============================================================================

/// Oracle-driven conditional payout using Rabin signatures.
///
/// Rabin signatures are a signature scheme that can be verified in Bitcoin
/// Script using only basic arithmetic opcodes (OP_MUL, OP_MOD). Unlike
/// ECDSA (which is hardcoded into OP_CHECKSIG), Rabin verification is
/// implemented as explicit script logic, enabling arbitrary message signing.
///
/// The oracle signs: num2bin(price, 8) -- the price as an 8-byte LE integer.
/// The contract only pays out if the oracle-attested price exceeds 50,000.
fn example_oracle_price_feed() -> Result<(), String> {
    separator("7. OraclePriceFeed -- Rabin Oracle Signature");
    let artifact = compile_from_source(Path::new("examples/ts/oracle-price/OraclePriceFeed.runar.ts"))?;
    print_summary(&artifact);

    let rabin_pk = "deadbeef".repeat(32); // 128-byte Rabin pubkey placeholder
    let receiver = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    let mut lock = Vec::new();
    lock.extend(&script_push_data(&from_hex(&rabin_pk)));
    lock.extend(&script_push_data(&from_hex(receiver)));
    lock.extend(&from_hex(&artifact.script));
    println!("\nDeploy: oraclePubKey={} bytes, locking: {} bytes", rabin_pk.len()/2, lock.len());

    let price: i64 = 55_000;
    println!("\n--- settle (price={}) ---", price);
    println!("  msg = num2bin(price, 8) = {}", to_hex(&(price as u64).to_le_bytes()));
    println!("  scriptSig: <price> <rabinSig> <padding> <sig>");
    println!("  1. verifyRabinSig(num2bin(price,8), rabinSig, padding, oraclePubKey)");
    println!("  2. assert(price > 50000)  -- threshold check");
    println!("  3. checkSig(sig, receiver) -- receiver authorization");
    println!("\n  price <= 50000 => FAIL (funds locked) | price > 50000 => OK (payout)");
    Ok(())
}

// ============================================================================
// 8. CovenantVault -- Covenant-enforced spending
// ============================================================================

/// Covenant-enforced spending: restricts HOW funds are spent, not just WHO.
///
/// Traditional Bitcoin scripts only control authorization (who can sign).
/// Covenants inspect the TRANSACTION ITSELF (via OP_PUSH_TX) to enforce
/// spending rules. This CovenantVault enforces a minimum output amount,
/// preventing the owner from creating dust outputs or draining below a
/// threshold -- even though they hold the private key.
fn example_covenant_vault() -> Result<(), String> {
    separator("8. CovenantVault -- Covenant-Enforced Spending");
    let artifact = compile_from_source(Path::new("examples/ts/covenant-vault/CovenantVault.runar.ts"))?;
    print_summary(&artifact);

    let owner = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let recipient = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
    let min_amount: i64 = 5_000;

    let mut lock = Vec::new();
    lock.extend(&script_push_data(&from_hex(owner)));
    lock.extend(&script_push_data(&from_hex(recipient)));
    lock.extend(&script_push_int(min_amount));
    lock.extend(&from_hex(&artifact.script));
    println!("\nDeploy: minAmount={}, locking: {} bytes", min_amount, lock.len());

    println!("\n--- spend (amount=7500) ---");
    println!("  scriptSig: <sig> <amount> <txPreimage>");
    println!("  1. checkSig(sig, owner)         -- authorization");
    println!("  2. checkPreimage(txPreimage)     -- OP_PUSH_TX");
    println!("  3. assert(amount >= {})   -- covenant: no dust", min_amount);

    println!("\n--- spend (amount=1000) ---");
    println!("  FAILS: 1000 < {} -- covenant rejects the transaction", min_amount);
    Ok(())
}

// ============================================================================
// Bonus: Compile from inline source string
// ============================================================================

/// Demonstrate compile_from_source_str: compile a contract from an inline
/// string without any file on disk. Useful for REPL tools, web playgrounds,
/// or dynamically generated contracts.
fn example_inline_compile() -> Result<(), String> {
    separator("Bonus: Inline Source Compilation");

    let source = r#"
import { SmartContract, assert, PubKey, Sig, checkSig } from 'runar-lang';

class SimpleLock extends SmartContract {
    readonly owner: PubKey;

    constructor(owner: PubKey) {
        super(owner);
        this.owner = owner;
    }

    public unlock(sig: Sig) {
        assert(checkSig(sig, this.owner));
    }
}
"#;
    println!("Compiling inline source ({} bytes)...", source.len());

    // compile_from_source_str takes the source text and an optional filename
    // (used for error messages). It runs the full 6-pass pipeline.
    let artifact = compile_from_source_str(source, Some("inline.runar.ts"))?;
    print_summary(&artifact);

    // The RunarArtifact is Serialize + Deserialize (serde), so you can
    // persist it as JSON for later use by wallets or deployment tools.
    let json = serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())?;
    println!("\nArtifact JSON ({} bytes):", json.len());
    let preview: String = json.chars().take(500).collect();
    println!("{}", preview);
    if json.len() > 500 { println!("... ({} more bytes)", json.len() - 500); }
    Ok(())
}

// ============================================================================
// OP_PUSH_TX Deep Dive
// ============================================================================

/// Explains the cryptographic mechanism behind stateful Rúnar contracts.
fn explain_op_push_tx() {
    separator("OP_PUSH_TX -- Deep Dive");
    println!("OP_PUSH_TX is a technique that lets a script inspect its own transaction.");
    println!("It exploits OP_CHECKSIG: the spender provides the sighash PREIMAGE as");
    println!("script input. The script extracts fields (outputs, locktime) from it,");
    println!("then OP_CHECKSIG verifies the preimage is authentic.\n");

    println!("--- Signature with privkey=1 ---");
    println!("  pubkey P = G (secp256k1 generator)");
    println!("  G  = 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    println!("  n  = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    println!("  r  = Gx (x-coordinate of generator)");
    println!("  s  = (sighash + r) mod n    [since privkey=1, nonce=1]");
    println!("  Verification: s*G = (z+r)*G = z*G + r*G = z*G + r*P  [P=G]\n");

    println!("--- BIP-143 Preimage (SIGHASH_ALL|FORKID = 0x41) ---");
    println!("  [4]  nVersion         [32] hashPrevouts    [32] hashSequence");
    println!("  [32] outpoint txid    [4]  outpoint vout   [var] scriptCode");
    println!("  [8]  value            [4]  nSequence       [32] hashOutputs");
    println!("  [4]  nLockTime        [4]  sighashType\n");

    println!("--- Stateful Contract Flow ---");
    println!("  1. Compute new state (e.g. count++ for Counter, owner=newOwner for Token)");
    println!("  2. getStateScript() serializes the updated locking script");
    println!("  3. hash256(stateScript) is compared against extractOutputHash(preimage)");
    println!("  4. extractOutputHash reads hashOutputs from the preimage (bytes at known offset)");
    println!("  5. If they match: the spending TX MUST produce an output with the new state");
    println!("  6. OP_CHECKSIG then verifies the preimage is authentic (not forged)");
    println!("  => The chain of UTXOs forms a state machine, each TX advancing the state.\n");

    println!("--- Which Rúnar contracts use OP_PUSH_TX? ---");
    println!("  Counter:       increment/decrement -- state = count");
    println!("  FungibleToken: transfer -- state = owner");
    println!("  NFT:           transfer -- state = owner (burn does NOT use it)");
    println!("  Auction:       bid -- state = highestBidder + highestBid (close does NOT)");
    println!("  CovenantVault: spend -- introspects tx to enforce minAmount");
    println!("  P2PKH:         does NOT use OP_PUSH_TX (stateless)");
    println!("  Escrow:        does NOT use OP_PUSH_TX (stateless, multi-method)");
    println!("  OraclePrice:   does NOT use OP_PUSH_TX (uses Rabin sigs instead)");
    println!("\n  Ref: https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX");
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!("Rúnar Rust SDK -- Comprehensive Usage Examples");
    println!("=============================================\n");

    let examples: Vec<(&str, fn() -> Result<(), String>)> = vec![
        ("P2PKH",           example_p2pkh),
        ("Escrow",          example_escrow),
        ("Counter",         example_counter),
        ("FungibleToken",   example_fungible_token),
        ("NFT",             example_nft),
        ("Auction",         example_auction),
        ("OraclePriceFeed", example_oracle_price_feed),
        ("CovenantVault",   example_covenant_vault),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (name, func) in &examples {
        match func() {
            Ok(()) => { println!("  [OK] {}", name); passed += 1; }
            Err(e) => { println!("  [FAIL] {}: {}", name, e); failed += 1; }
        }
    }

    match example_inline_compile() {
        Ok(()) => { println!("  [OK] Inline"); passed += 1; }
        Err(e) => { println!("  [FAIL] Inline: {}", e); failed += 1; }
    }

    explain_op_push_tx();

    separator("Summary");
    println!("  Passed: {} | Failed: {} | Total: {}", passed, failed, passed + failed);
    if failed > 0 { std::process::exit(1); }
}
