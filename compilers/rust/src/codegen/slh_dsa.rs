//! SLH-DSA (FIPS 205) Bitcoin Script codegen for the Rúnar Rust stack lowerer.
//!
//! Port of compilers/go/codegen/slh_dsa.go. All helpers are self-contained.
//! Entry: `emit_verify_slh_dsa()` emits the full verification script.
//!
//! Alt-stack convention: pkSeedPad (64 bytes) on alt permanently.
//! Tweakable hash pops pkSeedPad, DUPs, pushes copy back, uses original.
//!
//! Compile-time ADRS: treeAddr=0, keypair=0 where runtime values are needed.
//! WOTS+ chain hashAddress built dynamically from a counter on the stack.

use super::stack::{PushValue, StackOp};

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

    fn push_int(&mut self, n: &str, v: i64) {
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
        (self.e)(StackOp::Push(PushValue::Int(d as i64)));
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
        (self.e)(StackOp::Push(PushValue::Int(d as i64)));
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
// pkSeedPad on alt; pop, DUP, push back, use.

/// Emits a tracked tweakable hash.
#[allow(dead_code)]
fn emit_slh_t(t: &mut SLHTracker, n: usize, adrs: &str, msg: &str, result: &str) {
    t.to_top(adrs);
    t.to_top(msg);
    t.cat("_am");
    t.from_alt("_psp");
    t.dup("_psp2");
    t.to_alt();
    t.swap();
    t.cat("_pre");
    t.sha256("_h32");
    if n < 32 {
        t.push_int("", n as i64);
        t.split(result, "_tr");
        t.drop();
    } else {
        t.rename(result);
    }
}

/// Emits a raw tweakable hash. Stack: adrsC(1) msg(0) -> result(n). pkSeedPad on alt.
fn emit_slh_t_raw(e: &mut dyn FnMut(StackOp), n: usize) {
    e(StackOp::Opcode("OP_CAT".into()));
    e(StackOp::Opcode("OP_FROMALTSTACK".into()));
    e(StackOp::Dup);
    e(StackOp::Opcode("OP_TOALTSTACK".into()));
    e(StackOp::Swap);
    e(StackOp::Opcode("OP_CAT".into()));
    e(StackOp::Opcode("OP_SHA256".into()));
    if n < 32 {
        e(StackOp::Push(PushValue::Int(n as i64)));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
    }
}

// ===========================================================================
// 5. WOTS+ One Chain (tweakable hash, dynamic hashAddress)
// ===========================================================================

/// Returns one conditional hash step (if-then body).
///
/// Entry: sigElem(2) steps(1) hashAddr(0)
/// Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
fn slh_chain_step_then(adrs_prefix: &[u8], n: usize) -> Vec<StackOp> {
    let mut ops = Vec::new();
    // DUP hashAddr before consuming it in ADRS construction
    ops.push(StackOp::Dup);
    // Convert copy to 4-byte big-endian
    ops.push(StackOp::Push(PushValue::Int(4)));
    ops.push(StackOp::Opcode("OP_NUM2BIN".into()));
    ops.push(StackOp::Opcode("OP_REVERSE".into()));
    // Build ADRS = prefix(18) || hashAddrBE(4)
    ops.push(StackOp::Push(PushValue::Bytes(adrs_prefix.to_vec())));
    ops.push(StackOp::Swap);
    ops.push(StackOp::Opcode("OP_CAT".into()));
    // Move sigElem to top: ROLL 3
    ops.push(StackOp::Push(PushValue::Int(3)));
    ops.push(StackOp::Opcode("OP_ROLL".into()));
    // CAT: adrsC || sigElem
    ops.push(StackOp::Opcode("OP_CAT".into()));
    // pkSeedPad from alt
    ops.push(StackOp::Opcode("OP_FROMALTSTACK".into()));
    ops.push(StackOp::Dup);
    ops.push(StackOp::Opcode("OP_TOALTSTACK".into()));
    ops.push(StackOp::Swap);
    ops.push(StackOp::Opcode("OP_CAT".into()));
    ops.push(StackOp::Opcode("OP_SHA256".into()));
    if n < 32 {
        ops.push(StackOp::Push(PushValue::Int(n as i64)));
        ops.push(StackOp::Opcode("OP_SPLIT".into()));
        ops.push(StackOp::Drop);
    }
    // Rearrange -> newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
    ops.push(StackOp::Rot);
    ops.push(StackOp::Opcode("OP_1SUB".into()));
    ops.push(StackOp::Rot);
    ops.push(StackOp::Opcode("OP_1ADD".into()));
    // Save (hashAddr+1), swap bottom two, restore
    ops.push(StackOp::Opcode("OP_TOALTSTACK".into()));
    ops.push(StackOp::Swap);
    ops.push(StackOp::Opcode("OP_FROMALTSTACK".into()));
    ops
}

/// Emits one WOTS+ chain with tweakable hashing (raw opcodes).
///
/// Input:  sig(3) csum(2) endptAcc(1) digit(0)
/// Output: sigRest(2) newCsum(1) newEndptAcc(0)
/// Alt: pkSeedPad persists. 4 internal push/pop balanced.
fn emit_slh_one_chain(emit: &mut dyn FnMut(StackOp), n: usize, layer: usize, chain_idx: usize) {
    // steps = 15 - digit
    emit(StackOp::Push(PushValue::Int(15)));
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_SUB".into()));

    // Save steps_copy, endptAcc, csum to alt
    emit(StackOp::Dup);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: steps_copy
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: steps_copy, endptAcc
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: steps_copy, endptAcc, csum(top)

    // Split n-byte sig element
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(n as i64)));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // alt: ..., csum, sigRest(top)
    emit(StackOp::Swap);

    // Compute hashAddr = 15 - steps (= digit) on main stack
    emit(StackOp::Dup);
    emit(StackOp::Push(PushValue::Int(15)));
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_SUB".into()));

    // Build ADRS prefix for this chain
    let prefix = slh_adrs18(&SLHADRSOpts {
        layer,
        adrs_typ: SLH_WOTS_HASH,
        chain: chain_idx as i32,
        ..Default::default()
    });
    let then_ops = slh_chain_step_then(&prefix, n);

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

    // Restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // sigRest
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // csum
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // endptAcc
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // steps_copy

    // csum += steps_copy
    emit(StackOp::Rot);
    emit(StackOp::Opcode("OP_ADD".into()));

    // Cat endpoint to endptAcc
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(3)));
    emit(StackOp::Opcode("OP_ROLL".into()));
    emit(StackOp::Opcode("OP_CAT".into()));
}

// ===========================================================================
// Full WOTS+ Processing (all len chains)
// ===========================================================================
// Input:  wotsSig(len*n)(1) msg(n)(0)
// Output: wotsPk(n)

fn emit_slh_wots_all(emit: &mut dyn FnMut(StackOp), p: &SLHCodegenParams, layer: usize) {
    let n = p.n;
    let len1 = p.len1;
    let len2 = p.len2;

    // Rearrange: sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
    emit(StackOp::Swap);
    emit(StackOp::Push(PushValue::Int(0)));
    emit(StackOp::Opcode("OP_0".into()));
    emit(StackOp::Push(PushValue::Int(3)));
    emit(StackOp::Opcode("OP_ROLL".into()));

    // Process n bytes -> 2*n message chains
    for byte_idx in 0..n {
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

        if byte_idx < n - 1 {
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
            emit(StackOp::Swap);
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        } else {
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        }

        emit_slh_one_chain(emit, n, layer, byte_idx * 2);

        if byte_idx < n - 1 {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Swap);
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        } else {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        }

        emit_slh_one_chain(emit, n, layer, byte_idx * 2 + 1);

        if byte_idx < n - 1 {
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        }
    }

    // sigRest(2) totalCsum(1) endptAcc(0)
    // Checksum digits (len2=3)
    emit(StackOp::Swap);

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

    // sigRest(1) endptAcc(0) | alt: ..., d2, d1, d0(top)
    for ci in 0..len2 {
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));

        emit_slh_one_chain(emit, n, layer, len1 + ci);

        emit(StackOp::Swap);
        emit(StackOp::Drop);
    }

    // empty(1) endptAcc(0)
    emit(StackOp::Swap);
    emit(StackOp::Drop);

    // Compress -> wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc)
    let pk_adrs = slh_adrs(&SLHADRSOpts {
        layer,
        adrs_typ: SLH_WOTS_PK,
        ..Default::default()
    });
    emit(StackOp::Push(PushValue::Bytes(pk_adrs)));
    emit(StackOp::Swap);
    emit_slh_t_raw(emit, n);
}

// ===========================================================================
// 6. Merkle Auth Path Verification
// ===========================================================================
// Input:  leafIdx(2) authPath(hp*n)(1) node(n)(0)
// Output: root(n)

fn emit_slh_merkle(emit: &mut dyn FnMut(StackOp), p: &SLHCodegenParams, layer: usize) {
    let n = p.n;
    let hp = p.hp;

    // Move leafIdx to alt
    emit(StackOp::Push(PushValue::Int(2)));
    emit(StackOp::Opcode("OP_ROLL".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into()));

    for j in 0..hp {
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // node -> alt

        emit(StackOp::Push(PushValue::Int(n as i64)));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        emit(StackOp::Swap); // authPathRest authJ

        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // node

        // Get leafIdx
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit(StackOp::Dup);
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));

        // bit = (leafIdx >> j) & 1
        if j > 0 {
            emit(StackOp::Push(PushValue::Int(j as i64)));
            emit(StackOp::Opcode("OP_RSHIFT".into()));
        }
        emit(StackOp::Push(PushValue::Int(1)));
        emit(StackOp::Opcode("OP_AND".into()));

        let adrs = slh_adrs(&SLHADRSOpts {
            layer,
            adrs_typ: SLH_TREE,
            chain: (j + 1) as i32,
            hash: 0,
            ..Default::default()
        });

        let mut mk_tweak_hash = vec![
            StackOp::Push(PushValue::Bytes(adrs.clone())),
            StackOp::Swap,
            StackOp::Opcode("OP_CAT".into()),
            StackOp::Opcode("OP_FROMALTSTACK".into()),
            StackOp::Dup,
            StackOp::Opcode("OP_TOALTSTACK".into()),
            StackOp::Swap,
            StackOp::Opcode("OP_CAT".into()),
            StackOp::Opcode("OP_SHA256".into()),
        ];
        if n < 32 {
            mk_tweak_hash.push(StackOp::Push(PushValue::Int(n as i64)));
            mk_tweak_hash.push(StackOp::Opcode("OP_SPLIT".into()));
            mk_tweak_hash.push(StackOp::Drop);
        }

        let mut then_branch = vec![StackOp::Opcode("OP_CAT".into())];
        then_branch.extend(mk_tweak_hash.iter().cloned());

        let mut else_branch = vec![
            StackOp::Swap,
            StackOp::Opcode("OP_CAT".into()),
        ];
        else_branch.extend(mk_tweak_hash.iter().cloned());

        emit(StackOp::If {
            then_ops: then_branch,
            else_ops: else_branch,
        });
    }

    // Drop leafIdx from alt
    emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
    emit(StackOp::Drop);

    // authPathRest(empty)(1) root(0)
    emit(StackOp::Swap);
    emit(StackOp::Drop);
}

// ===========================================================================
// 7. FORS Verification
// ===========================================================================
// Input:  forsSig(k*(1+a)*n)(1) md(ceil(k*a/8))(0)
// Output: forsPk(n)

fn emit_slh_fors(emit: &mut dyn FnMut(StackOp), p: &SLHCodegenParams) {
    let n = p.n;
    let a = p.a;
    let k = p.k;

    // Save md to alt, push empty rootAcc to alt
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // md -> alt
    emit(StackOp::Opcode("OP_0".into()));
    emit(StackOp::Opcode("OP_TOALTSTACK".into())); // rootAcc(empty) -> alt

    for i in 0..k {
        // Get md: pop rootAcc, pop md, dup md, push md back, push rootAcc back
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // rootAcc
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // md
        emit(StackOp::Dup);
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // md back
        emit(StackOp::Swap);
        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // rootAcc back

        // Extract idx: `a` bits at position i*a from md_copy
        let bit_start = i * a;
        let byte_start = bit_start / 8;
        let bit_offset = bit_start % 8;
        let bits_in_first = std::cmp::min(8 - bit_offset, a);
        let take = if a > bits_in_first { 2 } else { 1 };

        if byte_start > 0 {
            emit(StackOp::Push(PushValue::Int(byte_start as i64)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Nip);
        }
        emit(StackOp::Push(PushValue::Int(take as i64)));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        emit(StackOp::Drop);
        if take > 1 {
            emit(StackOp::Opcode("OP_REVERSE".into()));
        }
        emit(StackOp::Push(PushValue::Int(0)));
        emit(StackOp::Push(PushValue::Int(1)));
        emit(StackOp::Opcode("OP_NUM2BIN".into()));
        emit(StackOp::Opcode("OP_CAT".into()));
        emit(StackOp::Opcode("OP_BIN2NUM".into()));
        let total_bits = take * 8;
        let right_shift = total_bits - bit_offset - a;
        if right_shift > 0 {
            emit(StackOp::Push(PushValue::Int(right_shift as i64)));
            emit(StackOp::Opcode("OP_RSHIFT".into()));
        }
        emit(StackOp::Push(PushValue::Int(((1i64 << a) - 1) as i64)));
        emit(StackOp::Opcode("OP_AND".into()));

        // Save idx to alt
        emit(StackOp::Opcode("OP_TOALTSTACK".into()));

        // Split sk(n) from sigRem
        emit(StackOp::Push(PushValue::Int(n as i64)));
        emit(StackOp::Opcode("OP_SPLIT".into()));
        emit(StackOp::Swap);

        // Leaf = T(pkSeed, ADRS_FORS_TREE{h=0}, sk)
        let leaf_adrs = slh_adrs(&SLHADRSOpts {
            adrs_typ: SLH_FORS_TREE,
            chain: 0,
            hash: 0,
            ..Default::default()
        });
        emit(StackOp::Push(PushValue::Bytes(leaf_adrs)));
        emit(StackOp::Swap);
        emit_slh_t_raw(emit, n);

        // Auth path walk: a levels
        for j in 0..a {
            emit(StackOp::Opcode("OP_TOALTSTACK".into())); // node -> alt

            emit(StackOp::Push(PushValue::Int(n as i64)));
            emit(StackOp::Opcode("OP_SPLIT".into()));
            emit(StackOp::Swap);

            emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // node

            // Get idx
            emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
            emit(StackOp::Dup);
            emit(StackOp::Opcode("OP_TOALTSTACK".into()));

            // bit = (idx >> j) & 1
            if j > 0 {
                emit(StackOp::Push(PushValue::Int(j as i64)));
                emit(StackOp::Opcode("OP_RSHIFT".into()));
            }
            emit(StackOp::Push(PushValue::Int(1)));
            emit(StackOp::Opcode("OP_AND".into()));

            let level_adrs = slh_adrs(&SLHADRSOpts {
                adrs_typ: SLH_FORS_TREE,
                chain: (j + 1) as i32,
                hash: 0,
                ..Default::default()
            });

            let mut hash_tail = vec![
                StackOp::Push(PushValue::Bytes(level_adrs)),
                StackOp::Swap,
                StackOp::Opcode("OP_CAT".into()),
                StackOp::Opcode("OP_FROMALTSTACK".into()),
                StackOp::Dup,
                StackOp::Opcode("OP_TOALTSTACK".into()),
                StackOp::Swap,
                StackOp::Opcode("OP_CAT".into()),
                StackOp::Opcode("OP_SHA256".into()),
            ];
            if n < 32 {
                hash_tail.push(StackOp::Push(PushValue::Int(n as i64)));
                hash_tail.push(StackOp::Opcode("OP_SPLIT".into()));
                hash_tail.push(StackOp::Drop);
            }

            let mut then_branch = vec![StackOp::Opcode("OP_CAT".into())];
            then_branch.extend(hash_tail.iter().cloned());

            let mut else_branch = vec![
                StackOp::Swap,
                StackOp::Opcode("OP_CAT".into()),
            ];
            else_branch.extend(hash_tail.iter().cloned());

            emit(StackOp::If {
                then_ops: then_branch,
                else_ops: else_branch,
            });
        }

        // Drop idx from alt
        emit(StackOp::Opcode("OP_FROMALTSTACK".into()));
        emit(StackOp::Drop);

        // Append treeRoot to rootAcc
        emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // rootAcc
        emit(StackOp::Swap);
        emit(StackOp::Opcode("OP_CAT".into()));

        emit(StackOp::Opcode("OP_TOALTSTACK".into())); // rootAcc -> alt
    }

    // Drop empty sigRest
    emit(StackOp::Drop);

    // Get rootAcc, drop md
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // rootAcc
    emit(StackOp::Opcode("OP_FROMALTSTACK".into())); // md
    emit(StackOp::Drop);

    // Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc)
    let fors_adrs = slh_adrs(&SLHADRSOpts {
        adrs_typ: SLH_FORS_ROOTS,
        ..Default::default()
    });
    emit(StackOp::Push(PushValue::Bytes(fors_adrs)));
    emit(StackOp::Swap);
    emit_slh_t_raw(emit, n);
}

// ===========================================================================
// 8. Hmsg -- Message Digest (SHA-256 MGF1)
// ===========================================================================
// Input:  R(3) pkSeed(2) pkRoot(1) msg(0)
// Output: digest(out_len bytes)

fn emit_slh_hmsg(emit: &mut dyn FnMut(StackOp), n: usize, out_len: usize) {
    let _ = n; // n unused in Hmsg but kept for API consistency with Go

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
            emit(StackOp::Push(PushValue::Int(out_len as i64)));
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
                    emit(StackOp::Push(PushValue::Int(rem as i64)));
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
    t.push_int("", n as i64);
    t.split("pkSeed", "pkRoot");

    // Build pkSeedPad = pkSeed || zeros(64-n), push to alt
    t.copy_to_top("pkSeed", "_psp");
    if 64 - n > 0 {
        t.push_bytes("", vec![0u8; 64 - n]);
        t.cat("_pkSeedPad");
    } else {
        t.rename("_pkSeedPad");
    }
    t.to_alt();

    // ---- 2. Parse R from sig ----
    t.to_top("sig");
    t.push_int("", n as i64);
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
    t.push_int("", md_len as i64);
    t.split("md", "_drest");

    t.to_top("_drest");
    t.push_int("", tree_idx_len as i64);
    t.split("_treeBytes", "_leafBytes");

    // Convert _treeBytes -> treeIdx
    t.to_top("_treeBytes");
    t.raw_block(&["_treeBytes"], "treeIdx", |e| {
        if tree_idx_len > 1 {
            e(StackOp::Opcode("OP_REVERSE".into()));
        }
        e(StackOp::Push(PushValue::Int(0)));
        e(StackOp::Push(PushValue::Int(1)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
        let shift = p.h - hp;
        // Compute mask safely: for shift >= 63, use i64::MAX
        let mask: i64 = if shift >= 63 {
            i64::MAX
        } else {
            (1i64 << shift) - 1
        };
        e(StackOp::Push(PushValue::Int(mask)));
        e(StackOp::Opcode("OP_AND".into()));
    });

    // Convert _leafBytes -> leafIdx
    t.to_top("_leafBytes");
    t.raw_block(&["_leafBytes"], "leafIdx", |e| {
        if leaf_idx_len > 1 {
            e(StackOp::Opcode("OP_REVERSE".into()));
        }
        e(StackOp::Push(PushValue::Int(0)));
        e(StackOp::Push(PushValue::Int(1)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
        let hp_mask: i64 = if hp >= 63 {
            i64::MAX
        } else {
            (1i64 << hp) - 1
        };
        e(StackOp::Push(PushValue::Int(hp_mask)));
        e(StackOp::Opcode("OP_AND".into()));
    });

    // ---- 5. Parse FORS sig ----
    t.to_top("sigRest");
    t.push_int("", fors_sig_len as i64);
    t.split("forsSig", "htSigRest");

    // ---- 6. FORS -> forsPk ----
    t.to_top("forsSig");
    t.to_top("md");
    t.raw_block(&["forsSig", "md"], "forsPk", |e| {
        emit_slh_fors(e, &p);
    });

    // ---- 7. Hypertree: d layers ----
    for layer in 0..d {
        // Split xmssSig from htSigRest
        t.to_top("htSigRest");
        t.push_int("", xmss_sig_len as i64);
        let xsig_name = format!("xsig{}", layer);
        t.split(&xsig_name, "htSigRest");

        // Split wotsSig and authPath
        t.to_top(&xsig_name);
        t.push_int("", (ln * n) as i64);
        let wsig_name = format!("wsig{}", layer);
        let auth_name = format!("auth{}", layer);
        t.split(&wsig_name, &auth_name);

        // WOTS+: wotsSig + currentMsg -> wotsPk
        let cur_msg = if layer == 0 {
            "forsPk".to_string()
        } else {
            format!("root{}", layer - 1)
        };
        t.to_top(&wsig_name);
        t.to_top(&cur_msg);
        let wpk_name = format!("wpk{}", layer);
        t.raw_block(&[&wsig_name, &cur_msg], &wpk_name, |e| {
            emit_slh_wots_all(e, &p, layer);
        });

        // Merkle: leafIdx + authPath + wotsPk -> root
        t.to_top("leafIdx");
        t.to_top(&auth_name);
        t.to_top(&wpk_name);
        let root_name = format!("root{}", layer);
        t.raw_block(&["leafIdx", &auth_name, &wpk_name], &root_name, |e| {
            emit_slh_merkle(e, &p, layer);
        });

        // Update leafIdx, treeIdx for next layer
        if layer < d - 1 {
            t.to_top("treeIdx");
            t.dup("_tic");
            let hp_mask: i64 = if hp >= 63 {
                i64::MAX
            } else {
                (1i64 << hp) - 1
            };
            t.push_int("", hp_mask);
            t.op("OP_AND");
            t.rename("leafIdx");

            t.to_top("_tic");
            t.push_int("", hp as i64);
            t.op("OP_RSHIFT");
            t.rename("treeIdx");
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
    let leftover = ["msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx"];
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
    // Pop pkSeedPad from alt
    t.from_alt("");
    t.drop();
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
        let prefix = slh_adrs18(&SLHADRSOpts {
            adrs_typ: SLH_WOTS_HASH,
            ..Default::default()
        });
        let ops = slh_chain_step_then(&prefix, 16);
        assert!(!ops.is_empty());
    }
}
