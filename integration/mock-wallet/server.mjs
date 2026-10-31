#!/usr/bin/env node
// ---------------------------------------------------------------------------
// integration/mock-wallet/server.mjs — in-repo BRC-100 test wallet (N-480).
//
// Serves the BRC-100 JSON-over-HTTP substrate (the wire shape @bsv/sdk's
// HTTPWalletJSON speaks: `POST {base}/{method}`, JSON request body, JSON
// response body) for exactly the two calls the seven tiers' wallet-client
// tests make:
//
//   getPublicKey  {protocolID, keyID, counterparty?, forSelf?, identityKey?}
//                 -> {publicKey}   real BRC-42 derivation via @bsv/sdk's
//                                  ProtoWallet over a fixed test root key
//   listOutputs   {basket, tags?, limit?, offset?}
//                 -> {totalOutputs, outputs: [{outpoint, satoshis,
//                    lockingScript, spendable}]}
//
// Requests are validated against the BRC-100 argument shapes; a malformed one
// gets HTTP 400 with the WERR_INVALID_PARAMETER body ({isError, code: 6,
// parameter, message}) that HTTPWalletJSON maps to a typed error. Every
// response, error or not, is JSON (HTTPWalletJSON parses the body before it
// looks at the status). Any other method is 404, any other verb 405.
//
// It is a TEST wallet: one fixed root key, no storage, no transactions. The
// basket always holds one output (so the clients' per-output shape checks run
// on something), locked to the root key's P2PKH script.
//
// Usage: node server.mjs [--port N]   (default 18480, binds 127.0.0.1)
// Normally started by ./mock-wallet.sh start.
// ---------------------------------------------------------------------------

import { createServer } from 'node:http';
import { PrivateKey, ProtoWallet, P2PKH } from '@bsv/sdk';

const portArg = process.argv.indexOf('--port');
const PORT = Number(portArg > 0 ? process.argv[portArg + 1] : process.env.MOCK_WALLET_PORT ?? 18480);
const HOST = '127.0.0.1';

// Fixed, publicly known test key. Never fund it.
const ROOT_KEY = PrivateKey.fromHex('4e2a5f0e1c3b7d9a8f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a1908');
const wallet = new ProtoWallet(ROOT_KEY);
const LOCKING_SCRIPT = new P2PKH().lock(ROOT_KEY.toPublicKey().toAddress()).toHex();
const OUTPUTS = [
  { outpoint: `${'ab'.repeat(32)}.0`, satoshis: 1000, lockingScript: LOCKING_SCRIPT, spendable: true },
];

class InvalidParameter extends Error {
  constructor(parameter, message) {
    super(message);
    this.parameter = parameter;
  }
}

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

function requireProtocolID(v) {
  if (!Array.isArray(v) || v.length !== 2 || ![0, 1, 2].includes(v[0]) || typeof v[1] !== 'string') {
    throw new InvalidParameter('protocolID', 'protocolID must be [0|1|2, string]');
  }
}

function optionalInt(args, name, min, max) {
  const v = args[name];
  if (v === undefined) return;
  if (!Number.isInteger(v) || v < min || v > max) {
    throw new InvalidParameter(name, `${name} must be an integer in [${min}, ${max}]`);
  }
}

const METHODS = {
  async getPublicKey(args) {
    if (args.identityKey !== true) {
      requireProtocolID(args.protocolID);
      if (typeof args.keyID !== 'string' || args.keyID.length === 0) {
        throw new InvalidParameter('keyID', 'keyID must be a non-empty string');
      }
    }
    try {
      return await wallet.getPublicKey(args);
    } catch (e) {
      // ProtoWallet's own key-derivation validation (protocol name rules, counterparty format).
      throw new InvalidParameter('args', e instanceof Error ? e.message : String(e));
    }
  },

  async listOutputs(args) {
    if (typeof args.basket !== 'string' || args.basket.length === 0) {
      throw new InvalidParameter('basket', 'basket must be a non-empty string');
    }
    if (args.tags !== undefined && (!Array.isArray(args.tags) || args.tags.some((t) => typeof t !== 'string'))) {
      throw new InvalidParameter('tags', 'tags must be an array of strings');
    }
    optionalInt(args, 'limit', 1, 10000);
    optionalInt(args, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const offset = args.offset ?? 0;
    const limit = args.limit ?? 10;
    return { totalOutputs: OUTPUTS.length, outputs: OUTPUTS.slice(offset, offset + limit) };
  },
};

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
  res.end(text);
}

const server = createServer((req, res) => {
  const method = (req.url ?? '').replace(/^\/+/, '').split('?')[0];
  if (req.method !== 'POST') {
    send(res, 405, { isError: true, message: `${req.method} not allowed; BRC-100 calls are POST` });
    return;
  }
  const handler = Object.hasOwn(METHODS, method) ? METHODS[method] : undefined;
  if (!handler) {
    send(res, 404, { isError: true, message: `unknown or unsupported BRC-100 method: ${method}` });
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    let args;
    try {
      args = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      send(res, 400, { isError: true, code: 6, parameter: 'args', message: 'request body is not JSON' });
      return;
    }
    try {
      if (!isObject(args)) throw new InvalidParameter('args', 'request body must be a JSON object');
      send(res, 200, await handler(args));
    } catch (e) {
      if (e instanceof InvalidParameter) {
        send(res, 400, { isError: true, code: 6, parameter: e.parameter, message: e.message });
      } else {
        send(res, 500, { isError: true, message: e instanceof Error ? e.message : String(e) });
      }
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`mock BRC-100 wallet listening on http://${HOST}:${PORT}`);
});
