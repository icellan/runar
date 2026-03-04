//! SLH-DSA (FIPS 205) Bitcoin Script codegen for the Rúnar Rust stack lowerer.
//!
//! Port of packages/runar-compiler/src/passes/slh-dsa-codegen.ts.
//! All helpers are self-contained.
//! Entry: `emit_verify_slh_dsa()` emits the full verification script.
//!
//! Main-stack convention: pkSeedPad (64 bytes) tracked as '_pkSeedPad' on the
//! main stack, accessed via PICK at known depth. Never placed on alt.
//!
//! Runtime ADRS: treeAddr (8-byte BE) and keypair (4-byte BE) are tracked on
//! the main stack as 'treeAddr8' and 'keypair4', threaded into rawBlocks.
//! ADRS is built at runtime using emit_build_adrs / emit_build_adrs18 helpers.

use super::stack::{PushValue, StackOp};

// ===========================================================================
// 0. Helpers
// ===========================================================================

/// Emit an unrolled fixed-length byte reversal for `n` bytes.
/// Uses (n-1) split-swap-cat operations. Only valid when n is known at compile time.
fn emit_reverse_n(n: usize) -> Vec<StackOp> {
    if n <= 1 {
        return vec![];
    }
    let mut ops = Vec::with_capacity(4 * (n - 1));
    // Phase 1: split into n individual bytes
    for _ in 0..n - 1 {
        ops.push(StackOp::Push(PushValue::Int(1)));
        ops.push(StackOp::Opcode("OP_SPLIT".into()));
    }
    // Phase 2: concatenate in reverse order
    for _ in 0..n - 1 {
        ops.push(StackOp::Swap);
        ops.push(StackOp::Opcode("OP_CAT".into()));
    }
    ops
}

/// Convert a compile-time integer to a 4-byte big-endian Vec<u8>.
fn int4be(v: usize) -> Vec<u8> {
    vec![
        ((v >> 24) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    ]
}

/// Collect ops into a Vec via closure.
fn collect_ops(f: impl FnOnce(&mut dyn FnMut(StackOp))) -> Vec<StackOp> {
    let mut ops = Vec::new();
    f(&mut |op| ops.push(op));
    ops
}

// ===========================================================================
// 1. Parameter Sets (FIPS 205 Table 1, SHA2)
// ===========================================================================

/// SLH-DSA parameter set for codegen.
#[derive(Debug, Clone, Copy)]
struct SLHCodegenParams {
    n: usize,    // Security parameter (hash bytes): 16, 24, 32
    h: usize,    // Total tree height
    d: usize,    // Hypertree layers
    hp: usize,   // Subtree height (h/d)
    a: usize,    // FORS tree height
    k: usize,    // FORS tree count
    #[allow(dead_code)]
    w: usize,    // Winternitz parameter (16)
    len: usize,  // WOTS+ chain count
    len1: usize, // Message chains (2*n)
    len2: usize, // Checksum chains (3 for all SHA2 sets)
}

fn slh_mk(n: usize, h: usize, d: usize, a: usize, k: usize) -> SLHCodegenParams {
    let len1 = 2 * n;
    let len2 = ((len1 as f64 * 15.0).log2() / 16.0_f64.log2()).floor() as usize + 1;
    SLHCodegenParams {
        n,
        h,
        d,
        hp: h / d,
        a,
        k,
        w: 16,
        len: len1 + len2,
        len1,
        len2,
    }
}

fn slh_params(key: &str) -> SLHCodegenParams {
    match key {
        "SHA2_128s" => slh_mk(16, 63, 7, 12, 14),
        "SHA2_128f" => slh_mk(16, 66, 22, 6, 33),
        "SHA2_192s" => slh_mk(24, 63, 7, 14, 17),
        "SHA2_192f" => slh_mk(24, 66, 22, 8, 33),
        "SHA2_256s" => slh_mk(32, 64, 8, 14, 22),
        "SHA2_256f" => slh_mk(32, 68, 17, 8, 35),
        _ => panic!("Unknown SLH-DSA params: {}", key),
    }
}

// ===========================================================================
// 2. Compressed ADRS (22 bytes)
// ===========================================================================
// [0] layer  [1..8] tree  [9] type  [10..13] keypair
// [14..17] chain/treeHeight  [18..21] hash/treeIndex

const SLH_WOTS_HASH: u8 = 0;
const SLH_WOTS_PK: u8 = 1;
const SLH_TREE: u8 = 2;
const SLH_FORS_TREE: u8 = 3;
const SLH_FORS_ROOTS: u8 = 4;

#[derive(Default)]
struct SLHADRSOpts {
    layer: usize,
    tree: i64,
    adrs_typ: u8,
    keypair: i32,
    chain: i32,
    hash: i32,
}

fn slh_adrs(opts: &SLHADRSOpts) -> Vec<u8> {
    let mut c = vec![0u8; 22];
    c[0] = (opts.layer & 0xff) as u8;
    let tr = opts.tree;
    for i in 0..8 {
        c[1 + 7 - i] = ((tr >> (8 * i)) & 0xff) as u8;
    }
    c[9] = opts.adrs_typ;
    let kp = opts.keypair;
    c[10] = ((kp >> 24) & 0xff) as u8;
    c[11] = ((kp >> 16) & 0xff) as u8;
    c[12] = ((kp >> 8) & 0xff) as u8;
    c[13] = (kp & 0xff) as u8;
    let ch = opts.chain;
    c[14] = ((ch >> 24) & 0xff) as u8;
    c[15] = ((ch >> 16) & 0xff) as u8;
    c[16] = ((ch >> 8) & 0xff) as u8;
    c[17] = (ch & 0xff) as u8;
    let ha = opts.hash;
    c[18] = ((ha >> 24) & 0xff) as u8;
    c[19] = ((ha >> 16) & 0xff) as u8;
    c[20] = ((ha >> 8) & 0xff) as u8;
    c[21] = (ha & 0xff) as u8;
    c
}

/// Returns the 18-byte prefix (bytes 0..17): everything before hashAddress.
fn slh_adrs18(opts: &SLHADRSOpts) -> Vec<u8> {
    let full = slh_adrs(&SLHADRSOpts {
        layer: opts.layer,
        tree: opts.tree,
        adrs_typ: opts.adrs_typ,
        keypair: opts.keypair,
        chain: opts.chain,
        hash: 0,
    });
    full[..18].to_vec()
}

// ===========================================================================
// 2b. Runtime ADRS builders
// ===========================================================================

/// Hash mode for emit_build_adrs.
enum HashMode {
    /// Append 4 zero bytes (hash=0). Net stack effect: +1.
    Zero,
    /// TOS has a 4-byte BE hash value; consumed and appended. Net stack effect: 0.
    Stack,
}

/// Emit runtime 18-byte ADRS prefix: layer(1B) || PICK(treeAddr8)(8B) ||
/// type(1B) || PICK(keypair4)(4B) || chain(4B).
///
/// Net stack effect: +1 (the 18-byte result on TOS).
///
/// ta8_depth and kp4_depth are from TOS *before* this function pushes anything.
fn emit_build_adrs18(
    emit: &mut dyn FnMut(StackOp),
    layer: usize,
    type_: u8,
    chain: usize,
    ta8_depth: usize,
    kp4_depth: Option<usize>,
) {
    // Push layer byte (1B)
    emit(StackOp::Push(PushValue::Bytes(vec![(layer & 0xff) as u8])));
    // After push: ta8 at ta8_depth+1, kp4 at kp4_depth+1

    // PICK ta8: depth = ta8_depth + 1 (one extra item on stack)
    let ta8_pick = ta8_depth + 1;
    emit(StackOp::Push(PushValue::Int(ta8_pick as i128)));
    emit(StackOp::Opcode("OP_PICK".into()));
    // Stack: ... layerByte ta8Copy (2 items above original TOS)
    emit(StackOp::Opcode("OP_CAT".into()));
    // Stack: ... (layer||ta8)(9B) -- net +1 from start
    // kp4 at kp4_depth + 1

    // Push type byte (1B)
    emit(StackOp::Push(PushValue::Bytes(vec![type_ & 0xff])));
    emit(StackOp::Opcode("OP_CAT".into()));
    // Stack: ... partial10B -- net +1
    // kp4 at kp4_depth + 1

    // keypair4: either PICK from stack or push 4 zero bytes
    match kp4_depth {
        Some(depth) => {
            let kp4_pick = depth + 1;
            emit(StackOp::Push(PushValue::Int(kp4_pick as i128)));
            emit(StackOp::Opcode("OP_PICK".into()));
        }
        None => {
            emit(StackOp::Push(PushValue::Bytes(vec![0, 0, 0, 0])));
        }
    }
    emit(StackOp::Opcode("OP_CAT".into()));
    // Stack: ... partial14B -- net +1

    // Push chain (4B BE)
    emit(StackOp::Push(PushValue::Bytes(int4be(chain))));
    emit(StackOp::Opcode("OP_CAT".into()));
    // Stack: ... prefix18B -- net +1
}

/// Emit runtime 22-byte ADRS.
///
/// hash mode:
///   Zero  -- append 4 zero bytes (hash=0). Net stack effect = +1 (22B ADRS on TOS).
///   Stack -- TOS has a 4-byte BE hash value; consumed and appended. Net stack effect = 0.
///
/// ta8_depth/kp4_depth measured from TOS before this function pushes anything.
fn emit_build_adrs(
    emit: &mut dyn FnMut(StackOp),
    layer: usize,
    type_: u8,
    chain: usize,
    ta8_depth: usize,
    kp4_depth: Option<usize>,
    hash: HashMode,
) {
    match hash {
        HashMode::Stack => {
            // Save hash4 from TOS to alt
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
            // Depths shift by -1 (one item removed from main)
            emit_build_adrs18(emit, layer, type_, chain, ta8_depth - 1, kp4_depth.map(|d| d - 1));
            // 18-byte prefix on TOS
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Opcode("OP_CAT".into()));
            // 22-byte ADRS on TOS. Net: replaced hash4 with adrs22.
        }
        HashMode::Zero => {
            emit_build_adrs18(emit, layer, type_, chain, ta8_depth, kp4_depth);
            emit(StackOp::Push(PushValue::Bytes(vec![0u8; 4])));
            emit(StackOp::Opcode("OP_CAT".into()));
            // 22-byte ADRS on TOS. Net: +1.
        }
    }
}

// ===========================================================================
// 3. SLH Stack Tracker
// ===========================================================================

/// Tracks named stack positions and emits StackOps.
struct SLHTracker<'a> {
    nm: Vec<String>,
    e: &'a mut dyn FnMut(StackOp),
}

#[allow(dead_code)]
impl<'a> SLHTracker<'a> {
    fn new(init: &[&str], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        SLHTracker {
            nm: init.iter().map(|s| s.to_string()).collect(),
            e: emit,
        }
    }

    fn depth(&self) -> usize {
        self.nm.len()
    }

    fn find_depth(&self, name: &str) -> usize {
        for i in (0..self.nm.len()).rev() {
            if self.nm[i] == name {
                return self.nm.len() - 1 - i;
            }
        }
        panic!("SLHTracker: '{}' not on stack {:?}", name, self.nm);
    }

    fn has(&self, name: &str) -> bool {
        self.nm.iter().any(|s| s == name)
    }

    fn push_bytes(&mut self, n: &str, v: Vec<u8>) {
        (self.e)(StackOp::Push(PushValue::Bytes(v)));
        self.nm.push(n.to_string());
    }

    fn push_int(&mut self, n: &str, v: i128) {
        (self.e)(StackOp::Push(PushValue::Int(v)));
        self.nm.push(n.to_string());
    }

    fn push_empty(&mut self, n: &str) {
        (self.e)(StackOp::Opcode("OP_0".into()));
        self.nm.push(n.to_string());
    }

    fn dup(&mut self, n: &str) {
        (self.e)(StackOp::Dup);
        self.nm.push(n.to_string());
    }

    fn drop(&mut self) {
        (self.e)(StackOp::Drop);
        if !self.nm.is_empty() {
            self.nm.pop();
        }
    }

    fn nip(&mut self) {
        (self.e)(StackOp::Nip);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.remove(len - 2);
        }
    }

    fn over(&mut self, n: &str) {
        (self.e)(StackOp::Over);
        self.nm.push(n.to_string());
    }

    fn swap(&mut self) {
        (self.e)(StackOp::Swap);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.swap(len - 1, len - 2);
        }
    }

    fn rot(&mut self) {
        (self.e)(StackOp::Rot);
        let len = self.nm.len();
        if len >= 3 {
            let r = self.nm.remove(len - 3);
            self.nm.push(r);
        }
    }

    fn op(&mut self, code: &str) {
        (self.e)(StackOp::Opcode(code.into()));
    }

    fn roll(&mut self, d: usize) {
        if d == 0 {
            return;
        }
        if d == 1 {
            self.swap();
            return;
        }
        if d == 2 {
            self.rot();
            return;
        }
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
        self.nm.push(String::new());
        (self.e)(StackOp::Opcode("OP_ROLL".into()));
        self.nm.pop(); // pop the push
        let idx = self.nm.len() - 1 - d;
        let r = self.nm.remove(idx);
        self.nm.push(r);
    }

    fn pick(&mut self, d: usize, n: &str) {
        if d == 0 {
            self.dup(n);
            return;
        }
        if d == 1 {
            self.over(n);
            return;
        }
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
        self.nm.push(String::new());
        (self.e)(StackOp::Opcode("OP_PICK".into()));
        self.nm.pop(); // pop the push
        self.nm.push(n.to_string());
    }

    fn to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        self.roll(d);
    }

    fn copy_to_top(&mut self, name: &str, n: &str) {
        let d = self.find_depth(name);
        self.pick(d, n);
    }

    fn to_alt(&mut self) {
        self.op("OP_TOALTSTACK");
        if !self.nm.is_empty() {
            self.nm.pop();
        }
    }

    fn from_alt(&mut self, n: &str) {
        self.op("OP_FROMALTSTACK");
        self.nm.push(n.to_string());
    }

    fn split(&mut self, left: &str, right: &str) {
        self.op("OP_SPLIT");
        // OP_SPLIT pops value + position, pushes left and right
        if !self.nm.is_empty() {
            self.nm.pop();
        }
        if !self.nm.is_empty() {
            self.nm.pop();
        }
        self.nm.push(left.to_string());
        self.nm.push(right.to_string());
    }

    fn cat(&mut self, n: &str) {
        self.op("OP_CAT");
        if self.nm.len() >= 2 {
            self.nm.truncate(self.nm.len() - 2);
        }
        self.nm.push(n.to_string());
    }

    fn sha256(&mut self, n: &str) {
        self.op("OP_SHA256");
        if !self.nm.is_empty() {
            self.nm.pop();
        }
        self.nm.push(n.to_string());
    }

    fn equal(&mut self, n: &str) {
        self.op("OP_EQUAL");
        if self.nm.len() >= 2 {
            self.nm.truncate(self.nm.len() - 2);
        }
        self.nm.push(n.to_string());
    }

    fn rename(&mut self, n: &str) {
        if let Some(last) = self.nm.last_mut() {
            *last = n.to_string();
        }
    }

    /// Emits raw opcodes; tracker only records net stack effect.
    fn raw_block(
        &mut self,
        consume: &[&str],
        produce: &str,
        f: impl FnOnce(&mut dyn FnMut(StackOp)),
    ) {
        for _ in consume {
            if !self.nm.is_empty() {
                self.nm.pop();
            }
        }
        f(self.e);
        if !produce.is_empty() {
            self.nm.push(produce.to_string());
        }
    }
}

// ===========================================================================
// 4. Tweakable Hash T(pkSeed, ADRS, M)
// ===========================================================================
// trunc_n(SHA-256(pkSeedPad(64) || ADRSc(22) || M))
// pkSeedPad on main stack, accessed via PICK.

/// Emits a tracked tweakable hash. Accesses _pkSeedPad via copy_to_top.
#[allow(dead_code)]
fn emit_slh_t(t: &mut SLHTracker, n: usize, adrs: &str, msg: &str, result: &str) {
    t.to_top(adrs);
    t.to_top(msg);
    t.cat("_am");
    // Access pkSeedPad via PICK on main stack
    t.copy_to_top("_pkSeedPad", "_psp");
    t.swap();
    t.cat("_pre");
    t.sha256("_h32");
    if n < 32 {
        t.push_int("", n as i128);
        t.split(result, "_tr");
        t.drop();
    } else {
        t.rename(result);
    }
}

/// Raw tweakable hash with pkSeedPad on main stack via PICK.
///
/// Stack in:  adrsC(1) msg(0), pkSeedPad at depth psp_depth from TOS
/// After CAT: (adrsC||msg)(0), pkSeedPad at depth psp_depth-1
/// PICK pkSeedPad, SWAP, CAT, SHA256, truncate
/// Stack out: result(0)
fn emit_slh_t_raw(e: &mut dyn FnMut(StackOp), n: usize, psp_depth: usize) {
    e(StackOp::Opcode("OP_CAT".into()));
    // After CAT: 2 consumed, 1 produced. pkSeedPad depth = psp_depth - 1.
    let pick_depth = psp_depth - 1;
    e(StackOp::Push(PushValue::Int(pick_depth as i128)));
    e(StackOp::Opcode("OP_PICK".into()));
    // pkSeedPad copy on TOS, original still in place
    e(StackOp::Swap);
    e(StackOp::Opcode("OP_CAT".into()));
    e(StackOp::Opcode("OP_SHA256".into()));
    if n < 32 {
        e(StackOp::Push(PushValue::Int(n as i128)));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
    }
}

// ===========================================================================
// 5. WOTS+ One Chain (tweakable hash, dynamic hashAddress)
// ===========================================================================

/// One conditional hash step (if-then body).
///
/// Entry: sigElem(2) steps(1) hashAddr(0)
///        with ADRS prefix (18B) on alt (FROMALT/DUP/TOALT pattern)
///        and pkSeedPad at psp_depth from TOS.
///
/// Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
fn slh_chain_step_then(n: usize, psp_depth: usize) -> Vec<StackOp> {
    let mut ops = Vec::new();
    // DUP hashAddr before consuming it in ADRS construction
    ops.push(StackOp::Dup);
    // sigElem(3) steps(2) hashAddr(1) hashAddr_copy(0)
    // Convert copy to 4-byte big-endian
    ops.push(StackOp::Push(PushValue::Int(4)));
    ops.push(StackOp::Opcode("OP_NUM2BIN".into()));
    ops.extend(emit_reverse_n(4));
    // sigElem(3) steps(2) hashAddr(1) hashAddrBE4(0) -- 4 items above base

    // Get prefix from alt: FROMALT; DUP; TOALT
    ops.push(StackOp::Opcode("OP_FROMALTSTACK".into()));
    ops.push(StackOp::Dup);
    ops.push(StackOp::Opcode("OP_TOALTSTACK".into()));
    // sigElem(4) steps(3) hashAddr(2) hashAddrBE4(1) prefix18(0) -- 5 items
    ops.push(StackOp::Swap);
    ops.push(StackOp::Opcode("OP_CAT".into()));
    // sigElem(3) steps(2) hashAddr(1) adrsC22(0) -- 4 items

    // Move sigElem to top: ROLL 3
    ops.push(StackOp::Push(PushValue::Int(3)));
    ops.push(StackOp::Opcode("OP_ROLL".into()));
    // steps(2) hashAddr(1) adrsC22(0) sigElem(top) -- 4 items
    // CAT: adrsC(1) || sigElem(0) -> adrsC||sigElem
    ops.push(StackOp::Opcode("OP_CAT".into()));
    // steps(1) hashAddr(0) (adrsC||sigElem)(top) -- 3 items

    // pkSeedPad via PICK (3 items on main above base, same as entry)
    ops.push(StackOp::Push(PushValue::Int(psp_depth as i128)));
    ops.push(StackOp::Opcode("OP_PICK".into()));
    // steps(2) hashAddr(1) (adrsC||sigElem)(0) pkSeedPad(top) -- 4 items
    ops.push(StackOp::Swap);
    // steps(2) hashAddr(1) pkSeedPad(0) (adrsC||sigElem)(top)
    ops.push(StackOp::Opcode("OP_CAT".into()));
    ops.push(StackOp::Opcode("OP_SHA256".into()));
    if n < 32 {
        ops.push(StackOp::Push(PushValue::Int(n as i128)));
        ops.push(StackOp::Opcode("OP_SPLIT".into()));
        ops.push(StackOp::Drop);
    }
    // steps(2) hashAddr(1) newSigElem(0) -- 3 items
    // Rearrange -> newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
    ops.push(StackOp::Rot);
    ops.push(StackOp::Opcode("OP_1SUB".into()));
    ops.push(StackOp::Rot);
    ops.push(StackOp::Opcode("OP_1ADD".into()));
    // newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
    ops
}

/// Emits one WOTS+ chain with tweakable hashing (raw opcodes).
///
/// Input:  sig(3) csum(2) endptAcc(1) digit(0)
///         pkSeedPad at psp_depth from TOS (digit)
///         treeAddr8 at ta8_depth from TOS
///         keypair4 at kp4_depth from TOS
///
/// Output: sigRest(2) newCsum(1) newEndptAcc(0)
///         (3 items replaces 4 input items, so depths shift by -1)
///
/// Alt: not used for pkSeedPad. Uses alt internally (balanced).
fn emit_slh_one_chain(
    emit: &mut dyn FnMut(StackOp),
    n: usize,
    layer: usize,
    chain_idx: usize,
    psp_depth: usize,
    ta8_depth: usize,
    kp4_depth: usize,
) {
    // Input: sig(3) csum(2) endptAcc(1) digit(0)

    // steps = 15 - digit
    emit(StackOp::Push(PushValue::Int(15)));
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_SUB".into()));
    // sig(3) csum(2) endptAcc(1) steps(0)

    // Save steps_copy, endptAcc, csum to alt
    emit(StackOp::Dup);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: steps_copy
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: steps_copy, endptAcc
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: steps_copy, endptAcc, csum(top)
    // main: sig(1) steps(0)
    // psp_d = psp_depth - 2 (4 items removed, 2 remain = -2)
    // ta8_d = ta8_depth - 2, kp4_d = kp4_depth - 2

    // Split n-byte sig element
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(n as i128)));
    emit(StackOp::Opcode("OP_SPLIT".into()));        // steps sigElem sigRest
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));   // alt: ..., csum, sigRest(top)
    emit(StackOp::Swap);
    // main: sigElem(1) steps(0)

    // Compute hashAddr = 15 - steps (= digit) on main stack
    emit(StackOp::Dup);
    emit(StackOp::Push(PushValue::Int(15)));
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_SUB".into()));
    // main: sigElem(2) steps(1) hashAddr(0) -- 3 items
    // psp_d_chain = psp_depth - 1
    let psp_d_chain = psp_depth - 1;
    let ta8_d_chain = ta8_depth - 1;
    let kp4_d_chain = kp4_depth - 1;

    // Build 18-byte ADRS prefix using runtime treeAddr8 and keypair4
    // After emit_build_adrs18: +1 item on stack => 4 items: sigElem steps hashAddr prefix18
    emit_build_adrs18(emit, layer, SLH_WOTS_HASH, chain_idx, ta8_d_chain, Some(kp4_d_chain));
    // psp_d = psp_d_chain + 1 = psp_depth
    // Save prefix18 to alt for loop reuse
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));
    // main: sigElem(2) steps(1) hashAddr(0) -- back to 3 items
    // psp_d = psp_d_chain = psp_depth - 1

    // Build then-ops for chain step
    // At step entry: sigElem(2) steps(1) hashAddr(0), 3 items above base
    // psp_d at step entry = psp_depth - 1
    let then_ops = slh_chain_step_then(n, psp_d_chain);

    // 15 unrolled conditional hash iterations
    for _ in 0..15 {
        emit(StackOp::Over);
        emit(StackOp::Opcode("OP_0NOTEQUAL".into()));
        emit(StackOp::If {
            then_ops: then_ops.clone(),
            else_ops: vec![],
        });
    }

    // endpoint(2) 0(1) finalHashAddr(0)
    emit(StackOp::Drop);
    emit(StackOp::Drop);
    // main: endpoint

    // Drop prefix from alt
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
    emit(StackOp::Drop);

    // Restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // sigRest
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // csum
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // endptAcc
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // steps_copy
    // bottom->top: endpoint sigRest csum endptAcc steps_copy

    // csum += steps_copy: ROT top-3 to bring csum up
    emit(StackOp::Rot);
    emit(StackOp::Opcode("OP_ADD".into()));

    // Cat endpoint to endptAcc
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(3)));
    emit(StackOp::Opcode("OP_ROLL".into()));
    emit(StackOp::Opcode("OP_CAT".into()));
    // sigRest(2) newCsum(1) newEndptAcc(0)
}

// ===========================================================================
// Full WOTS+ Processing (all len chains)
// ===========================================================================
// Input:  psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
// Output: psp(3) ta8(2) kp4(1) wotsPk(0)

fn emit_slh_wots_all(emit: &mut dyn FnMut(StackOp), p: &SLHCodegenParams, layer: usize) {
    let n = p.n;
    let len1 = p.len1;
    let len2 = p.len2;

    // Input: psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
    // Rearrange: psp(6) ta8(5) kp4(4) sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(0)));
    emit(StackOp::Opcode("OP_0".into()));
    emit(StackOp::Push(PushValue::Int(3)));
    emit(StackOp::Opcode("OP_ROLL".into()));
    // psp(6) ta8(5) kp4(4) sigRem(3) csum(2) endptAcc(1) msgRem(0)
    // pspD=6, ta8D=5, kp4D=4

    // Process n bytes -> 2*n message chains
    for byte_idx in 0..n {
        // State: psp(6) ta8(5) kp4(4) sigRem(3) csum(2) endptAcc(1) msgRem(0)
        if byte_idx < n - 1 {
            emit(StackOp::Push(PushValue::Int(1)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Swap);
        }
        // Unsigned byte conversion
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Push(PushValue::Int(1)));
        emit(StackOp::Opcode("OP_NUM2BIN".into()));
        emit(StackOp::Opcode("OP_CAT".into()));
        emit(StackOp::Opcode("OP_BIN2NUM".into()));
        // High/low nibbles
        emit(StackOp::Dup);
        emit(StackOp::Push(PushValue::Int(16)));
        emit(StackOp::Opcode("OP_DIV".into()));
        emit(StackOp::Swap);
        emit(StackOp::Push(PushValue::Int(16)));
        emit(StackOp::Opcode("OP_MOD".into()));
        // Stack: ..kp4 sig csum endptAcc [msgRest if non-last] hiNib loNib

        if byte_idx < n - 1 {
            // Stack: psp ta8 kp4 sig csum endptAcc msgRest hiNib loNib
            emit(StackOp::Opcode("OP_TOALTSTACK".into())); // loNib -> alt
            emit(StackOp::Swap);                             // msgRest hiNib -> hiNib msgRest
            emit(StackOp::Opcode("OP_TOALTSTACK".into())); // msgRest -> alt
            // Stack: psp(6) ta8(5) kp4(4) sig(3) csum(2) endptAcc(1) hiNib(0)
            // pspD=6, ta8D=5, kp4D=4
        } else {
            // Stack: psp ta8 kp4 sig csum endptAcc hiNib loNib
            emit(StackOp::Opcode("OP_TOALTSTACK".into())); // loNib -> alt
            // Stack: psp(6) ta8(5) kp4(4) sig(3) csum(2) endptAcc(1) hiNib(0)
        }

        // First chain call (hiNib)
        // sig(3) csum(2) endptAcc(1) digit=hiNib(0), pspD=6, ta8D=5, kp4D=4
        emit_slh_one_chain(emit, n, layer, byte_idx * 2, 6, 5, 4);
        // Output: sigRest(2) newCsum(1) newEndptAcc(0)
        // pspD=5, ta8D=4, kp4D=3

        if byte_idx < n - 1 {
            // Restore loNib and msgRest from alt
            emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // msgRest
            emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // loNib
            emit(StackOp::Swap);
            emit(StackOp::Opcode("OP_TOALTSTACK".into())); // msgRest -> alt
            // Stack: psp(6) ta8(5) kp4(4) sigRest(3) newCsum(2) newEndptAcc(1) loNib(0)
        } else {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // loNib
            // Stack: psp(6) ta8(5) kp4(4) sigRest(3) newCsum(2) newEndptAcc(1) loNib(0)
        }

        // Second chain call (loNib)
        emit_slh_one_chain(emit, n, layer, byte_idx * 2 + 1, 6, 5, 4);
        // Output: sigRest(2) newCsum(1) newEndptAcc(0)
        // pspD=5, ta8D=4, kp4D=3

        if byte_idx < n - 1 {
            // Restore msgRest from alt
            emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // msgRest
            // Stack: psp(6) ta8(5) kp4(4) sigRest(3) csum(2) endptAcc(1) msgRest(0)
        }
        // Back to shape: psp(6) ta8(5) kp4(4) sigRest(3) csum(2) endptAcc(1) msgRem(0)
    }

    // After all message chains: psp(5) ta8(4) kp4(3) sigRest(2) totalCsum(1) endptAcc(0)
    // Checksum digits (len2=3)
    emit(StackOp::Swap);
    // psp(5) ta8(4) kp4(3) sigRest(2) endptAcc(1) totalCsum(0)

    emit(StackOp::Dup);
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));

    emit(StackOp::Dup);
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_DIV".into()));
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));

    emit(StackOp::Push(PushValue::Int(256)));
    emit(StackOp::Opcode("OP_DIV".into()));
    emit(StackOp::Push(PushValue::Int(16)));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));
    // psp(4) ta8(3) kp4(2) sigRest(1) endptAcc(0) | alt: d2, d1, d0(top)

    for ci in 0..len2 {
        // psp(4) ta8(3) kp4(2) sigRest(1) endptAcc(0)
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // endptAcc -> alt
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // endptAcc
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // digit
        // psp(6) ta8(5) kp4(4) sigRest(3) 0(2) endptAcc(1) digit(0)

        emit_slh_one_chain(emit, n, layer, len1 + ci, 6, 5, 4);
        // sigRest(2) newCsum(1) newEndptAcc(0) -- pspD=5, ta8D=4, kp4D=3

        emit(StackOp::Swap);
        emit(StackOp::Drop);
        // psp(4) ta8(3) kp4(2) sigRest(1) newEndptAcc(0)
    }

    // psp(4) ta8(3) kp4(2) empty(1) endptAcc(0)
    emit(StackOp::Swap);
    emit(StackOp::Drop);
    // psp(3) ta8(2) kp4(1) endptAcc(0)

    // Compress -> wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc)
    // Build ADRS: ta8 at depth 2, kp4 at depth 1 (from endptAcc which is TOS)
    emit_build_adrs(emit, layer, SLH_WOTS_PK, 0, 2, None, HashMode::Zero);
    // psp(4) ta8(3) kp4(2) endptAcc(1) adrs22(0)
    emit(StackOp::Swap);
    // psp(4) ta8(3) kp4(2) adrs22(1) endptAcc(0)
    emit_slh_t_raw(emit, n, 4);
    // psp(3) ta8(2) kp4(1) wotsPk(0)
}

// ===========================================================================
// 6. Merkle Auth Path Verification
// ===========================================================================
// Input:  psp(5) ta8(4) kp4(3) leafIdx(2) authPath(hp*n)(1) node(n)(0)
// Output: psp(3) ta8(2) kp4(1) root(0)

fn emit_slh_merkle(emit: &mut dyn FnMut(StackOp), p: &SLHCodegenParams, layer: usize) {
    let n = p.n;
    let hp = p.hp;

    // Input: psp(5) ta8(4) kp4(3) leafIdx(2) authPath(1) node(0)
    // Move leafIdx to alt
    emit(StackOp::Push(PushValue::Int(2)));
    emit(StackOp::Opcode("OP_ROLL".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));
    // psp(4) ta8(3) kp4(2) authPath(1) node(0) | alt: leafIdx

    for j in 0..hp {
        // psp(4) ta8(3) kp4(2) authPath(1) node(0)
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // node -> alt

        emit(StackOp::Push(PushValue::Int(n as i128)));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        emit(StackOp::Swap); // authPathRest authJ

        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // node
        // psp(4) ta8(3) kp4(2) authPathRest(2) authJ(1) node(0)

        // Get leafIdx
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit(StackOp::Dup);
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        // psp(5) ta8(4) kp4(3) authPathRest(3) authJ(2) node(1) leafIdx(0)

        // bit = (leafIdx >> j) % 2
        if j > 0 {
            emit(StackOp::Push(PushValue::Int((1i128 << j) as i128)));
            emit(StackOp::Opcode("OP_DIV".into()));
        }
        emit(StackOp::Push(PushValue::Int(2)));
        emit(StackOp::Opcode("OP_MOD".into()));

        // Build the tweakable hash ops for both branches.
        // After CAT in branch: authPathRest(1) children(0)
        // psp(3) ta8(2) kp4(1) authPathRest(1) children(0)
        // pspD=3, ta8D=2, kp4D=1

        // Need ADRS with hash = leafIdx >> (j+1) as 4-byte BE
        // Build hash: get leafIdx from alt, shift, convert to 4B BE
        let mk_tweak_hash: Vec<StackOp> = collect_ops(|e| {
            // Stack in: authPathRest(1) children(0)
            // pspD=4, ta8D=3, kp4D=2

            // Get leafIdx from alt to compute hash
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
            e(StackOp::Dup);
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            // authPathRest(2) children(1) leafIdx(0); pspD=5, ta8D=4, kp4D=3
            if j + 1 > 0 {
                e(StackOp::Push(PushValue::Int((1i128 << (j + 1)) as i128)));
                e(StackOp::Opcode("OP_DIV".into()));
            }
            // Convert to 4-byte BE
            e(StackOp::Push(PushValue::Int(4)));
            e(StackOp::Opcode("OP_NUM2BIN".into()));
            for op in emit_reverse_n(4) {
                e(op);
            }
            // authPathRest(2) children(1) hash4BE(0); pspD=5, ta8D=4, kp4D=3

            // Build ADRS (22B) with hash=Stack
            emit_build_adrs(e, layer, SLH_TREE, j + 1, 4, None, HashMode::Stack);
            // Net 0 (hash4 replaced by adrs22). pspD=5, ta8D=4, kp4D=3
            // authPathRest(2) children(1) adrs22(0)
            e(StackOp::Swap);
            // authPathRest(2) adrs22(1) children(0)
            // Now tweakable hash: adrs(1) msg(0) -> result. pspD=5
            emit_slh_t_raw(e, n, 5);
            // authPathRest(1) result(0); pspD=4
        });

        let mut then_branch = vec![
            // bit==1: authJ||node. Stack: authJ(1) node(0). CAT -> authJ||node.
            StackOp::Opcode("OP_CAT".into()),
        ];
        then_branch.extend(mk_tweak_hash.iter().cloned());

        let mut else_branch = vec![
            // bit==0: node||authJ. Stack: authJ(1) node(0). SWAP -> node(1) authJ(0). CAT -> node||authJ.
            StackOp::Swap,
            StackOp::Opcode("OP_CAT".into()),
        ];
        else_branch.extend(mk_tweak_hash.iter().cloned());

        emit(StackOp::If {
            then_ops: then_branch,
            else_ops: else_branch,
        });
        // psp(3) ta8(2) kp4(1) authPathRest(1) result(0) | alt: leafIdx
    }

    // Drop leafIdx from alt
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
    emit(StackOp::Drop);

    // psp ta8 kp4 authPathRest root -- 5 items after FROMALT+DROP
    // SWAP: psp ta8 kp4 root authPathRest
    // DROP: psp ta8 kp4 root -- 4 items
    // psp(3) ta8(2) kp4(1) root(0)
    emit(StackOp::Swap);
    emit(StackOp::Drop);
}

// ===========================================================================
// 7. FORS Verification
// ===========================================================================
// Input:  psp(4) ta8(3) kp4(2) forsSig(1) md(0)
// Output: psp(3) ta8(2) kp4(1) forsPk(0)

fn emit_slh_fors(emit: &mut dyn FnMut(StackOp), p: &SLHCodegenParams) {
    let n = p.n;
    let a = p.a;
    let k = p.k;

    // Input: psp(4) ta8(3) kp4(2) forsSig(1) md(0)
    // Save md to alt, push empty rootAcc to alt
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));     // md -> alt
    emit(StackOp::Opcode("OP_0".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));     // rootAcc(empty) -> alt
    // psp(3) ta8(2) kp4(1) forsSig(0) | alt: md, rootAcc(top)
    // pspD=3, ta8D=2, kp4D=1

    for i in 0..k {
        // psp(3) ta8(2) kp4(1) forsSigRem(0) | alt: md, rootAcc

        // Get md: pop rootAcc, pop md, dup md, push md back, push rootAcc back
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // rootAcc
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // md
        emit(StackOp::Dup);
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));   // md back
        emit(StackOp::Swap);
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));   // rootAcc back
        // psp(4) ta8(3) kp4(2) forsSigRem(1) md_copy(0)

        // Extract idx: `a` bits at position i*a from md_copy
        let bit_start = i * a;
        let byte_start = bit_start / 8;
        let bit_offset = bit_start % 8;
        let bits_in_first = std::cmp::min(8 - bit_offset, a);
        let take = if a > bits_in_first { 2 } else { 1 };

        if byte_start > 0 {
            emit(StackOp::Push(PushValue::Int(byte_start as i128)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Nip);
        }
        emit(StackOp::Push(PushValue::Int(take as i128)));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        emit(StackOp::Drop);
        if take > 1 {
            for op in emit_reverse_n(take) {
                emit(op);
            }
        }
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Push(PushValue::Int(1)));
        emit(StackOp::Opcode("OP_NUM2BIN".into()));
        emit(StackOp::Opcode("OP_CAT".into()));
        emit(StackOp::Opcode("OP_BIN2NUM".into()));
        let total_bits = take * 8;
        let right_shift = total_bits - bit_offset - a;
        if right_shift > 0 {
            emit(StackOp::Push(PushValue::Int((1i128 << right_shift) as i128)));
            emit(StackOp::Opcode("OP_DIV".into()));
        }
        // Use OP_MOD instead of OP_AND to avoid byte-length mismatch
        emit(StackOp::Push(PushValue::Int(1i128 << a)));
        emit(StackOp::Opcode("OP_MOD".into()));
        // psp(4) ta8(3) kp4(2) forsSigRem(1) idx(0)

        // Save idx to alt (above rootAcc)
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        // psp(3) ta8(2) kp4(1) forsSigRem(0) | alt: md, rootAcc, idx(top)

        // Split sk(n) from sigRem
        emit(StackOp::Push(PushValue::Int(n as i128)));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        emit(StackOp::Swap);
        // psp(4) ta8(3) kp4(2) sigRest(1) sk(0)

        // Leaf = T(pkSeed, ADRS_FORS_TREE{chain=0, hash=runtime}, sk)
        // The FORS leaf hash index is: i * (1<<a) + idx
        // Need to get idx from alt, compute, convert to 4B BE, build ADRS
        // Get idx from alt (above rootAcc)
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // idx
        emit(StackOp::Dup);
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // idx back
        // psp(5) ta8(4) kp4(3) sigRest(2) sk(1) idx(0)

        // Compute hash = i*(1<<a) + idx
        if i > 0 {
            emit(StackOp::Push(PushValue::Int((i * (1 << a)) as i128)));
            emit(StackOp::Opcode("OP_ADD".into()));
        }
        // Convert to 4B BE
        emit(StackOp::Push(PushValue::Int(4)));
        emit(StackOp::Opcode("OP_NUM2BIN".into()));
        for op in emit_reverse_n(4) {
            emit(op);
        }
        // psp(5) ta8(4) kp4(3) sigRest(2) sk(1) hash4BE(0)

        // Build ADRS with hash=Stack: ta8D=4, kp4D=3
        emit_build_adrs(emit, 0, SLH_FORS_TREE, 0, 4, Some(3), HashMode::Stack);
        // hash4 replaced by adrs22. psp(5) ta8(4) kp4(3) sigRest(2) sk(1) adrs22(0)
        emit(StackOp::Swap);
        // psp(5) ta8(4) kp4(3) sigRest(2) adrs22(1) sk(0)
        emit_slh_t_raw(emit, n, 5);
        // psp(4) ta8(3) kp4(2) sigRest(1) node(0)

        // Auth path walk: a levels
        for j in 0..a {
            // psp(4) ta8(3) kp4(2) sigRest(1) node(0)
            emit(StackOp::Opcode("OP_TOALTSTACK".into())); // node -> alt

            emit(StackOp::Push(PushValue::Int(n as i128)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Swap);
            // sigRest authJ

            emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // node
            // psp(4) ta8(3) kp4(2) sigRest(2) authJ(1) node(0)

            // Get idx: pop from alt (idx is top of alt), dup, push back
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Dup);
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
            // psp(5) ta8(4) kp4(3) sigRest(3) authJ(2) node(1) idx(0)

            // bit = (idx >> j) % 2
            if j > 0 {
                emit(StackOp::Push(PushValue::Int((1i128 << j) as i128)));
                emit(StackOp::Opcode("OP_DIV".into()));
            }
            emit(StackOp::Push(PushValue::Int(2)));
            emit(StackOp::Opcode("OP_MOD".into()));

            // After if/then branches: CAT children -> children(0)
            // psp(4) ta8(3) kp4(2) sigRest(1) children(0)
            // Need tweakable hash with ADRS. hash = i*(1<<(a-j-1)) + (idx >> (j+1))
            let mk_fors_auth_hash: Vec<StackOp> = collect_ops(|e| {
                // Stack: sigRest(1) children(0)
                // pspD=4, ta8D=3, kp4D=2

                // Get idx from alt to compute hash
                e(StackOp::Opcode("OP_FROMALTSTACK".into()));
                e(StackOp::Dup);
                e(StackOp::Opcode("OP_TOALTSTACK".into()));
                // sigRest(2) children(1) idx(0); pspD=5, ta8D=4, kp4D=3
                // hash = i*(1<<(a-j-1)) + (idx >> (j+1))
                if j + 1 > 0 {
                    e(StackOp::Push(PushValue::Int((1i128 << (j + 1)) as i128)));
                    e(StackOp::Opcode("OP_DIV".into()));
                }
                let base = i * (1 << (a - j - 1));
                if base > 0 {
                    e(StackOp::Push(PushValue::Int(base as i128)));
                    e(StackOp::Opcode("OP_ADD".into()));
                }
                // Convert to 4B BE
                e(StackOp::Push(PushValue::Int(4)));
                e(StackOp::Opcode("OP_NUM2BIN".into()));
                for op in emit_reverse_n(4) {
                    e(op);
                }
                // sigRest(2) children(1) hash4BE(0); ta8D=4, kp4D=3

                // Build ADRS with hash=Stack
                emit_build_adrs(e, 0, SLH_FORS_TREE, j + 1, 4, Some(3), HashMode::Stack);
                // sigRest(2) children(1) adrs22(0); pspD=5, ta8D=4, kp4D=3
                e(StackOp::Swap);
                emit_slh_t_raw(e, n, 5);
                // sigRest(1) result(0); pspD=4
            });

            let mut then_branch = vec![StackOp::Opcode("OP_CAT".into())];
            then_branch.extend(mk_fors_auth_hash.iter().cloned());

            let mut else_branch = vec![
                StackOp::Swap,
                StackOp::Opcode("OP_CAT".into()),
            ];
            else_branch.extend(mk_fors_auth_hash.iter().cloned());

            emit(StackOp::If {
                then_ops: then_branch,
                else_ops: else_branch,
            });
            // psp(4) ta8(3) kp4(2) sigRest(1) result(0)
        }

        // psp(4) ta8(3) kp4(2) sigRest(1) treeRoot(0) | alt: md, rootAcc, idx

        // Drop idx from alt
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit(StackOp::Drop);

        // Append treeRoot to rootAcc
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // rootAcc
        emit(StackOp::Swap);
        emit(StackOp::Opcode("OP_CAT".into()));
        // psp(3) ta8(2) kp4(1) sigRest(1) newRootAcc(0)

        emit(StackOp::Opcode("OP_TOALTSTACK".into()));   // rootAcc -> alt
        // psp(3) ta8(2) kp4(1) sigRest(0) | alt: md, newRootAcc
    }

    // Drop empty sigRest
    emit(StackOp::Drop);

    // Get rootAcc, drop md
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));   // rootAcc
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));   // md
    emit(StackOp::Drop);
    // psp ta8 kp4 rootAcc md -> after drop md: psp ta8 kp4 rootAcc
    // psp(3) ta8(2) kp4(1) rootAcc(0)

    // Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc)
    // Build ADRS: ta8D=2, kp4D=1
    emit_build_adrs(emit, 0, SLH_FORS_ROOTS, 0, 2, Some(1), HashMode::Zero);
    // psp(4) ta8(3) kp4(2) rootAcc(1) adrs22(0)
    emit(StackOp::Swap);
    emit_slh_t_raw(emit, n, 4);
    // psp(3) ta8(2) kp4(1) forsPk(0)
}

// ===========================================================================
// 8. Hmsg -- Message Digest (SHA-256 MGF1)
// ===========================================================================
// Input:  R(3) pkSeed(2) pkRoot(1) msg(0)
// Output: digest(out_len bytes)

fn emit_slh_hmsg(emit: &mut dyn FnMut(StackOp), n: usize, out_len: usize) {
    let _ = n; // n unused in Hmsg but kept for API consistency

    // CAT: R || pkSeed || pkRoot || msg
    emit(StackOp::Opcode("OP_CAT".into()));
    emit(StackOp::Opcode("OP_CAT".into()));
    emit(StackOp::Opcode("OP_CAT".into()));
    emit(StackOp::Opcode("OP_SHA256".into())); // seed(32B)

    let blocks = (out_len + 31) / 32;
    if blocks == 1 {
        emit(StackOp::Push(PushValue::Bytes(vec![0u8; 4])));
        emit(StackOp::Opcode("OP_CAT".into()));
        emit(StackOp::Opcode("OP_SHA256".into()));
        if out_len < 32 {
            emit(StackOp::Push(PushValue::Int(out_len as i128)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Drop);
        }
    } else {
        emit(StackOp::Opcode("OP_0".into())); // resultAcc
        emit(StackOp::Swap);                   // resultAcc seed

        for ctr in 0..blocks {
            if ctr < blocks - 1 {
                emit(StackOp::Dup);
            }
            let ctr_bytes = vec![
                ((ctr >> 24) & 0xff) as u8,
                ((ctr >> 16) & 0xff) as u8,
                ((ctr >> 8) & 0xff) as u8,
                (ctr & 0xff) as u8,
            ];
            emit(StackOp::Push(PushValue::Bytes(ctr_bytes)));
            emit(StackOp::Opcode("OP_CAT".into()));
            emit(StackOp::Opcode("OP_SHA256".into()));

            if ctr == blocks - 1 {
                let rem = out_len - ctr * 32;
                if rem < 32 {
                    emit(StackOp::Push(PushValue::Int(rem as i128)));
                    emit(StackOp::Opcode("OP_SPLIT".into()));
                    emit(StackOp::Drop);
                }
            }

            if ctr < blocks - 1 {
                emit(StackOp::Rot);
                emit(StackOp::Swap);
                emit(StackOp::Opcode("OP_CAT".into()));
                emit(StackOp::Swap);
            } else {
                emit(StackOp::Swap);
                emit(StackOp::Opcode("OP_CAT".into()));
            }
        }
    }
}

// ===========================================================================
// 9. Main Entry -- emit_verify_slh_dsa
// ===========================================================================
// Input:  msg(2) sig(1) pubkey(0)  [pubkey on top]
// Output: boolean

/// Emits the full SLH-DSA verification script.
pub fn emit_verify_slh_dsa(emit: &mut dyn FnMut(StackOp), param_key: &str) {
    let p = slh_params(param_key);

    let n = p.n;
    let d = p.d;
    let hp = p.hp;
    let k = p.k;
    let a = p.a;
    let ln = p.len;
    let fors_sig_len = k * (1 + a) * n;
    let xmss_sig_len = (ln + hp) * n;
    let md_len = (k * a + 7) / 8;
    let tree_idx_len = (p.h - hp + 7) / 8;
    let leaf_idx_len = (hp + 7) / 8;
    let digest_len = md_len + tree_idx_len + leaf_idx_len;

    let mut t = SLHTracker::new(&["msg", "sig", "pubkey"], emit);

    // ---- 1. Parse pubkey -> pkSeed, pkRoot ----
    t.to_top("pubkey");
    t.push_int("", n as i128);
    t.split("pkSeed", "pkRoot");

    // Build pkSeedPad = pkSeed || zeros(64-n), keep on main stack
    t.copy_to_top("pkSeed", "_psp");
    if 64 - n > 0 {
        t.push_bytes("", vec![0u8; 64 - n]);
        t.cat("_pkSeedPad");
    } else {
        t.rename("_pkSeedPad");
    }
    // _pkSeedPad stays on main stack (tracked)

    // ---- 2. Parse R from sig ----
    t.to_top("sig");
    t.push_int("", n as i128);
    t.split("R", "sigRest");

    // ---- 3. Compute Hmsg(R, pkSeed, pkRoot, msg) ----
    t.copy_to_top("R", "_R");
    t.copy_to_top("pkSeed", "_pks");
    t.copy_to_top("pkRoot", "_pkr");
    t.copy_to_top("msg", "_msg");
    t.raw_block(&["_R", "_pks", "_pkr", "_msg"], "digest", |e| {
        emit_slh_hmsg(e, n, digest_len);
    });

    // ---- 4. Extract md, treeIdx, leafIdx ----
    t.to_top("digest");
    t.push_int("", md_len as i128);
    t.split("md", "_drest");

    t.to_top("_drest");
    t.push_int("", tree_idx_len as i128);
    t.split("_treeBytes", "_leafBytes");

    // Convert _treeBytes -> treeIdx
    t.to_top("_treeBytes");
    t.raw_block(&["_treeBytes"], "treeIdx", |e| {
        if tree_idx_len > 1 {
            for op in emit_reverse_n(tree_idx_len) {
                e(op);
            }
        }
        e(StackOp::Push(PushValue::Int(0)));
        e(StackOp::Push(PushValue::Int(1)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
        // Use OP_MOD instead of OP_AND to avoid byte-length mismatch
        let shift = p.h - hp;
        let modulus: i128 = if shift >= 127 {
            i128::MAX
        } else {
            1i128 << shift
        };
        e(StackOp::Push(PushValue::Int(modulus)));
        e(StackOp::Opcode("OP_MOD".into()));
    });

    // Convert _leafBytes -> leafIdx
    t.to_top("_leafBytes");
    t.raw_block(&["_leafBytes"], "leafIdx", |e| {
        if leaf_idx_len > 1 {
            for op in emit_reverse_n(leaf_idx_len) {
                e(op);
            }
        }
        e(StackOp::Push(PushValue::Int(0)));
        e(StackOp::Push(PushValue::Int(1)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
        // Use OP_MOD instead of OP_AND to avoid byte-length mismatch
        let hp_modulus: i128 = if hp >= 127 {
            i128::MAX
        } else {
            1i128 << hp
        };
        e(StackOp::Push(PushValue::Int(hp_modulus)));
        e(StackOp::Opcode("OP_MOD".into()));
    });

    // ---- 4b. Compute treeAddr8 and keypair4 for ADRS construction ----
    // treeAddr8 = treeIdx as 8-byte big-endian
    t.copy_to_top("treeIdx", "_ti8");
    t.raw_block(&["_ti8"], "treeAddr8", |e| {
        e(StackOp::Push(PushValue::Int(8)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        for op in emit_reverse_n(8) {
            e(op);
        }
    });

    // keypair4 = leafIdx as 4-byte big-endian
    t.copy_to_top("leafIdx", "_li4");
    t.raw_block(&["_li4"], "keypair4", |e| {
        e(StackOp::Push(PushValue::Int(4)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        for op in emit_reverse_n(4) {
            e(op);
        }
    });

    // ---- 5. Parse FORS sig ----
    t.to_top("sigRest");
    t.push_int("", fors_sig_len as i128);
    t.split("forsSig", "htSigRest");

    // ---- 6. FORS -> forsPk ----
    // Copy psp/ta8/kp4 to top, then forsSig, md
    t.copy_to_top("_pkSeedPad", "_psp");
    t.copy_to_top("treeAddr8", "_ta");
    t.copy_to_top("keypair4", "_kp");
    t.to_top("forsSig");
    t.to_top("md");
    t.raw_block(&["_psp", "_ta", "_kp", "forsSig", "md"], "forsPk", |e| {
        // Stack: psp(4) ta8(3) kp4(2) forsSig(1) md(0)
        emit_slh_fors(e, &p);
        // Stack: psp(3) ta8(2) kp4(1) forsPk(0)
        // Drop psp, ta8, kp4
        e(StackOp::Opcode("OP_TOALTSTACK".into())); // forsPk -> alt
        e(StackOp::Drop); // kp4
        e(StackOp::Drop); // ta8
        e(StackOp::Drop); // psp
        e(StackOp::Opcode("OP_FROMALTSTACK".into())); // forsPk back
    });

    // ---- 7. Hypertree: d layers ----
    for layer in 0..d {
        // Split xmssSig from htSigRest
        t.to_top("htSigRest");
        t.push_int("", xmss_sig_len as i128);
        let xsig_name = format!("xsig{}", layer);
        t.split(&xsig_name, "htSigRest");

        // Split wotsSig and authPath
        t.to_top(&xsig_name);
        t.push_int("", (ln * n) as i128);
        let wsig_name = format!("wsig{}", layer);
        let auth_name = format!("auth{}", layer);
        t.split(&wsig_name, &auth_name);

        // WOTS+: copy psp/ta8/kp4 + wotsSig + currentMsg -> wotsPk
        let cur_msg = if layer == 0 {
            "forsPk".to_string()
        } else {
            format!("root{}", layer - 1)
        };
        t.copy_to_top("_pkSeedPad", "_psp");
        t.copy_to_top("treeAddr8", "_ta");
        t.copy_to_top("keypair4", "_kp");
        t.to_top(&wsig_name);
        t.to_top(&cur_msg);
        let wpk_name = format!("wpk{}", layer);
        t.raw_block(&["_psp", "_ta", "_kp", &wsig_name, &cur_msg], &wpk_name, |e| {
            // Stack: psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
            emit_slh_wots_all(e, &p, layer);
            // Stack: psp(3) ta8(2) kp4(1) wotsPk(0)
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            e(StackOp::Drop); e(StackOp::Drop); e(StackOp::Drop);
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
        });

        // Merkle: copy psp/ta8/kp4 + leafIdx + authPath + wotsPk -> root
        t.copy_to_top("_pkSeedPad", "_psp");
        t.copy_to_top("treeAddr8", "_ta");
        t.copy_to_top("keypair4", "_kp");
        t.to_top("leafIdx");
        t.to_top(&auth_name);
        t.to_top(&wpk_name);
        let root_name = format!("root{}", layer);
        t.raw_block(&["_psp", "_ta", "_kp", "leafIdx", &auth_name, &wpk_name], &root_name, |e| {
            // Stack: psp(5) ta8(4) kp4(3) leafIdx(2) authPath(1) node(0)
            emit_slh_merkle(e, &p, layer);
            // Stack: psp(3) ta8(2) kp4(1) root(0)
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            e(StackOp::Drop); e(StackOp::Drop); e(StackOp::Drop);
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
        });

        // Update leafIdx, treeIdx, treeAddr8, keypair4 for next layer
        if layer < d - 1 {
            t.to_top("treeIdx");
            t.dup("_tic");
            // leafIdx = _tic % (1 << hp)
            t.raw_block(&["_tic"], "leafIdx", |e| {
                e(StackOp::Push(PushValue::Int(1i128 << hp)));
                e(StackOp::Opcode("OP_MOD".into()));
            });
            // treeIdx = treeIdx >> hp
            t.swap();
            t.raw_block(&["treeIdx"], "treeIdx", |e| {
                e(StackOp::Push(PushValue::Int((1i128 << hp) as i128)));
                e(StackOp::Opcode("OP_DIV".into()));
            });

            // Update treeAddr8 = new treeIdx as 8-byte BE
            // Drop old treeAddr8
            t.to_top("treeAddr8");
            t.drop();
            t.copy_to_top("treeIdx", "_ti8");
            t.raw_block(&["_ti8"], "treeAddr8", |e| {
                e(StackOp::Push(PushValue::Int(8)));
                e(StackOp::Opcode("OP_NUM2BIN".into()));
                for op in emit_reverse_n(8) {
                    e(op);
                }
            });

            // Update keypair4 = new leafIdx as 4-byte BE
            // Drop old keypair4
            t.to_top("keypair4");
            t.drop();
            t.copy_to_top("leafIdx", "_li4");
            t.raw_block(&["_li4"], "keypair4", |e| {
                e(StackOp::Push(PushValue::Int(4)));
                e(StackOp::Opcode("OP_NUM2BIN".into()));
                for op in emit_reverse_n(4) {
                    e(op);
                }
            });
        }
    }

    // ---- 8. Compare root to pkRoot ----
    let final_root = format!("root{}", d - 1);
    t.to_top(&final_root);
    t.to_top("pkRoot");
    t.equal("_result");

    // ---- 9. Cleanup ----
    t.to_top("_result");
    t.to_alt();

    // Drop all remaining tracked values
    let leftover = [
        "msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
        "_pkSeedPad", "treeAddr8", "keypair4",
    ];
    for nm in &leftover {
        if t.has(nm) {
            t.to_top(nm);
            t.drop();
        }
    }
    while t.depth() > 0 {
        t.drop();
    }

    t.from_alt("_result");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_params_exist() {
        for key in &[
            "SHA2_128s",
            "SHA2_128f",
            "SHA2_192s",
            "SHA2_192f",
            "SHA2_256s",
            "SHA2_256f",
        ] {
            let p = slh_params(key);
            assert!(p.n > 0);
            assert!(p.len > 0);
            assert_eq!(p.hp, p.h / p.d);
        }
    }

    #[test]
    fn test_adrs_22_bytes() {
        let a = slh_adrs(&SLHADRSOpts {
            layer: 3,
            tree: 42,
            adrs_typ: SLH_WOTS_HASH,
            keypair: 7,
            chain: 5,
            hash: 9,
        });
        assert_eq!(a.len(), 22);
        assert_eq!(a[0], 3); // layer
        assert_eq!(a[9], SLH_WOTS_HASH); // type
    }

    #[test]
    fn test_adrs18_prefix() {
        let a18 = slh_adrs18(&SLHADRSOpts {
            layer: 1,
            adrs_typ: SLH_WOTS_HASH,
            chain: 2,
            ..Default::default()
        });
        assert_eq!(a18.len(), 18);
    }

    #[test]
    fn test_emit_verify_slh_dsa_produces_ops() {
        let mut ops = Vec::new();
        emit_verify_slh_dsa(&mut |op| ops.push(op), "SHA2_128s");
        assert!(!ops.is_empty(), "should produce stack ops");
    }

    #[test]
    fn test_chain_step_then() {
        let ops = slh_chain_step_then(16, 6);
        assert!(!ops.is_empty());
    }
}
