let state = null;
let busy = false;

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
    state = await api('POST', '/api/init');
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
