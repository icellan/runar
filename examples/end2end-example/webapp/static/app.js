let state = null;
let busy = false;

// ---------------------------------------------------------------------------
// Language selection + playground (M17)
// ---------------------------------------------------------------------------
//
// The backend dispatches Rúnar source parsing on the file extension, so the
// frontend just passes the short language key through to /api/init and
// /api/compile. The supported set matches compiler.go#sourceLangs:
//   ts, sol, move, go, rs, py, rb, zig, java.
//
// Java is the newest addition (milestone M17). Its default template mirrors
// examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java.

const PLAYGROUND_TEMPLATES = {
  java: [
    'package runar.examples.p2pkh;',
    '',
    'import runar.lang.SmartContract;',
    'import runar.lang.annotations.Public;',
    'import runar.lang.annotations.Readonly;',
    'import runar.lang.types.Addr;',
    'import runar.lang.types.PubKey;',
    'import runar.lang.types.Sig;',
    '',
    'import static runar.lang.Builtins.assertThat;',
    'import static runar.lang.Builtins.checkSig;',
    'import static runar.lang.Builtins.hash160;',
    '',
    '// Contract classes in .runar.java files are package-private so javac',
    '// accepts the compound .runar.java suffix.',
    'class P2PKH extends SmartContract {',
    '',
    '    @Readonly Addr pubKeyHash;',
    '',
    '    P2PKH(Addr pubKeyHash) {',
    '        super(pubKeyHash);',
    '        this.pubKeyHash = pubKeyHash;',
    '    }',
    '',
    '    @Public',
    '    void unlock(Sig sig, PubKey pubKey) {',
    '        assertThat(hash160(pubKey).equals(pubKeyHash));',
    '        assertThat(checkSig(sig, pubKey));',
    '    }',
    '}',
    '',
  ].join('\n'),
  ts: [
    "import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';",
    '',
    'class P2PKH extends SmartContract {',
    '  readonly pubKeyHash: Addr;',
    '',
    '  constructor(pubKeyHash: Addr) {',
    '    super(pubKeyHash);',
    '    this.pubKeyHash = pubKeyHash;',
    '  }',
    '',
    '  public unlock(sig: Sig, pubKey: PubKey) {',
    '    assert(hash160(pubKey) == this.pubKeyHash);',
    '    assert(checkSig(sig, pubKey));',
    '  }',
    '}',
    '',
  ].join('\n'),
};

const LANG_FILENAMES = {
  ts: 'P2PKH.runar.ts',
  sol: 'P2PKH.runar.sol',
  move: 'P2PKH.runar.move',
  go: 'P2PKH.runar.go',
  rs: 'P2PKH.runar.rs',
  py: 'P2PKH.runar.py',
  rb: 'P2PKH.runar.rb',
  zig: 'P2PKH.runar.zig',
  java: 'P2PKH.runar.java',
};

function selectedInitLang() {
  const el = document.getElementById('lang-select');
  return (el && el.value) || 'ts';
}

function selectedPlaygroundLang() {
  const el = document.getElementById('pg-lang-select');
  return (el && el.value) || 'java';
}

function togglePlayground() {
  const init = document.getElementById('init-screen');
  const pg = document.getElementById('playground-screen');
  if (pg.classList.contains('hidden')) {
    init.classList.add('hidden');
    pg.classList.remove('hidden');
    if (!document.getElementById('pg-source').value) {
      loadTemplate();
    }
  } else {
    pg.classList.add('hidden');
    init.classList.remove('hidden');
  }
}

function loadTemplate() {
  const lang = selectedPlaygroundLang();
  const ta = document.getElementById('pg-source');
  ta.value = PLAYGROUND_TEMPLATES[lang] || PLAYGROUND_TEMPLATES.java;
  const res = document.getElementById('pg-result');
  while (res.firstChild) res.removeChild(res.firstChild);
}

function pgResultAppendLabel(parent, text) {
  const d = document.createElement('div');
  d.className = 'pg-label';
  d.textContent = text;
  parent.appendChild(d);
}

function pgResultAppendPre(parent, text, cls) {
  const pre = document.createElement('pre');
  pre.className = cls;
  pre.textContent = text;
  parent.appendChild(pre);
}

async function compileSource() {
  const lang = selectedPlaygroundLang();
  const source = document.getElementById('pg-source').value;
  const resultEl = document.getElementById('pg-result');
  while (resultEl.firstChild) resultEl.removeChild(resultEl.firstChild);
  const spinner = document.createElement('div');
  spinner.className = 'pg-status';
  const spinnerIcon = document.createElement('span');
  spinnerIcon.className = 'loading';
  spinner.appendChild(spinnerIcon);
  spinner.appendChild(document.createTextNode(' Compiling ' + lang + '...'));
  resultEl.appendChild(spinner);
  try {
    const data = await api('POST', '/api/compile', {
      source,
      lang,
      filename: LANG_FILENAMES[lang] || '',
    });
    while (resultEl.firstChild) resultEl.removeChild(resultEl.firstChild);
    const ok = document.createElement('div');
    ok.className = 'pg-ok';
    ok.textContent = 'Compiled ' + data.filename;
    resultEl.appendChild(ok);
    pgResultAppendLabel(resultEl, 'Script hex (' + (data.scriptHex.length / 2) + ' bytes)');
    pgResultAppendPre(resultEl, data.scriptHex, 'pg-hex');
    pgResultAppendLabel(resultEl, 'Script asm');
    pgResultAppendPre(resultEl, data.scriptAsm, 'pg-asm');
  } catch (e) {
    while (resultEl.firstChild) resultEl.removeChild(resultEl.firstChild);
    const err = document.createElement('div');
    err.className = 'pg-err';
    err.textContent = 'Compile failed: ' + e.message;
    resultEl.appendChild(err);
  }
}

function setStatus(msg) {
  document.getElementById('status').textContent = msg;
}

function setLoading(msg) {
  document.getElementById('status').innerHTML =
    '<span class="loading"></span>' + msg;
}

function satsToDisplay(sats) {
  const btc = (sats / 1e8).toFixed(4);
  return { btc, sats: sats.toLocaleString() };
}

function updateBalances() {
  if (!state) return;
  const a = satsToDisplay(state.aliceBalance);
  document.getElementById('alice-btc').textContent = a.btc;
  document.getElementById('alice-sats').textContent = a.sats;

  const b = satsToDisplay(state.bobBalance);
  document.getElementById('bob-btc').textContent = b.btc;
  document.getElementById('bob-sats').textContent = b.sats;
}

function renderLog() {
  if (!state || !state.log) return;
  const container = document.getElementById('tx-log-entries');
  container.innerHTML = '';

  for (const entry of state.log) {
    const div = document.createElement('div');
    div.className = 'tx-log-entry';

    const icons = { fund: '\u2713', deploy: '\u25C6', reveal: '\u2605', round: '\u25CB' };
    const icon = icons[entry.type] || '\u00B7';

    let txHtml = '';
    if (entry.txid) {
      txHtml = '<span class="txid">txid: ' + entry.txid + '</span>';
    }

    div.innerHTML =
      '<span class="icon ' + entry.type + '">' + icon + '</span>' +
      '<span class="msg">' + entry.message + '</span>' +
      txHtml;

    container.appendChild(div);
  }

  container.scrollTop = container.scrollHeight;
}

function showBetChoice(player, choice) {
  const el = document.getElementById(player + '-choice');
  el.className = '';
  el.classList.remove('hidden');
  el.innerHTML = '<span class="bet-choice ' + choice + '">' + choice.toUpperCase() + '</span>';
}

async function api(method, path, body) {
  const opts = { method };
  if (body) {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data.error || 'request failed');
  }
  return data;
}

async function initGame() {
  if (busy) return;
  busy = true;
  const btn = document.getElementById('btn-init');
  btn.disabled = true;
  btn.textContent = 'Initializing...';

  try {
    state = await api('POST', '/api/init', { lang: selectedInitLang() });
    document.getElementById('init-screen').classList.add('hidden');
    document.getElementById('game-screen').classList.remove('hidden');
    updateBalances();
    renderLog();
    busy = false;
    newRound();
  } catch (e) {
    btn.disabled = false;
    btn.textContent = 'Initialize Game';
    busy = false;
    alert('Init failed: ' + e.message);
  }
}

async function newRound() {
  if (busy) return;
  busy = true;

  resetRoundUI();
  setLoading('Starting new round...');

  try {
    state = await api('POST', '/api/round/new');
    document.getElementById('round-number').textContent = state.round;
    document.getElementById('threshold-area').classList.remove('hidden');
    document.getElementById('oracle-area').classList.remove('hidden');
    animateThreshold(state.threshold);
    renderLog();
  } catch (e) {
    setStatus('Error: ' + e.message);
  } finally {
    busy = false;
  }
}

function resetRoundUI() {
  document.getElementById('threshold-area').classList.add('hidden');
  document.getElementById('oracle-area').classList.add('hidden');
  document.getElementById('reveal-area').classList.add('hidden');
  document.getElementById('result-area').classList.add('hidden');
  document.getElementById('alice-buttons').classList.add('hidden');
  document.getElementById('bob-buttons').classList.add('hidden');
  document.getElementById('alice-choice').classList.add('hidden');
  document.getElementById('bob-choice').classList.add('hidden');
  document.getElementById('oracle-box').textContent = '???';
  document.getElementById('oracle-box').className = 'oracle-box';

  document.getElementById('alice-panel').classList.remove('winner', 'loser');
  document.getElementById('bob-panel').classList.remove('winner', 'loser');
  setStatus('');
}

function animateThreshold(target) {
  const el = document.getElementById('threshold-value');
  let count = 0;
  const duration = 1000;
  const interval = 50;
  const steps = duration / interval;

  const timer = setInterval(() => {
    count++;
    if (count >= steps) {
      clearInterval(timer);
      el.textContent = target;
      showBettingUI();
    } else {
      el.textContent = Math.floor(Math.random() * 100) + 1;
    }
  }, interval);
}

function showBettingUI() {
  document.getElementById('alice-buttons').classList.remove('hidden');
  document.getElementById('bob-buttons').classList.add('hidden');
  setStatus('Alice: pick OVER or UNDER');
}

async function placeBet(player, choice) {
  if (busy) return;
  busy = true;

  setLoading(player === 'alice' ? 'Alice bets ' + choice + '...' : 'Bob bets ' + choice + '...');

  try {
    state = await api('POST', '/api/round/bet', { player, choice });
    updateBalances();
    renderLog();

    showBetChoice('alice', state.aliceBet);
    showBetChoice('bob', state.bobBet);

    document.getElementById('alice-buttons').classList.add('hidden');
    document.getElementById('bob-buttons').classList.add('hidden');

    if (state.phase === 'deployed') {
      setStatus('Contract deployed! Ready to reveal.');
      document.getElementById('reveal-area').classList.remove('hidden');
    } else {
      document.getElementById('bob-buttons').classList.remove('hidden');
      setStatus('Bob: pick your bet');
    }
  } catch (e) {
    setStatus('Error: ' + e.message);
  } finally {
    busy = false;
  }
}

async function revealOracle() {
  if (busy) return;
  busy = true;

  document.getElementById('reveal-area').classList.add('hidden');
  setLoading('Revealing oracle number...');

  const oracleBox = document.getElementById('oracle-box');
  oracleBox.classList.add('rolling');

  await new Promise(resolve => {
    let ticks = 0;
    const maxTicks = 30;
    const timer = setInterval(() => {
      ticks++;
      oracleBox.textContent = Math.floor(Math.random() * 100) + 1;
      if (ticks >= maxTicks) {
        clearInterval(timer);
        resolve();
      }
    }, 60);
  });

  try {
    const result = await api('POST', '/api/round/reveal');
    state = result.state;

    oracleBox.classList.remove('rolling');
    oracleBox.textContent = result.oracle;

    const overWins = result.oracle > state.history[state.history.length - 1].threshold;
    oracleBox.classList.add(overWins ? 'winner-over' : 'winner-under');

    updateBalances();
    renderLog();

    const banner = document.getElementById('result-banner');
    const winnerName = result.winner.charAt(0).toUpperCase() + result.winner.slice(1);
    banner.textContent = winnerName + ' wins 20,000 sats!';
    banner.className = 'result-banner win';
    document.getElementById('result-area').classList.remove('hidden');

    if (result.winner === 'alice') {
      document.getElementById('alice-panel').classList.add('winner');
      document.getElementById('bob-panel').classList.add('loser');
    } else {
      document.getElementById('bob-panel').classList.add('winner');
      document.getElementById('alice-panel').classList.add('loser');
    }

    setStatus('Round complete!');
  } catch (e) {
    oracleBox.classList.remove('rolling');
    oracleBox.textContent = 'ERR';
    setStatus('Error: ' + e.message);
  } finally {
    busy = false;
  }
}
