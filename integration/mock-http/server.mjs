#!/usr/bin/env node
// ---------------------------------------------------------------------------
// integration/mock-http/server.mjs — deterministic HTTP echo server (N-485).
//
// Stands in for httpbin.org in the Zig SDK's live-GET tests
// (packages/runar-zig/src/sdk_http_client.zig). `GET /get` answers 200 with
// httpbin's shape, reflecting the request's Host header:
//
//   {"url": "http://<Host>/get", "headers": {"Host": "<Host>"}}
//
// Any other path is 404, any other verb 405. No dependencies.
//
// Usage: node server.mjs [--port N]   (default 18481, binds 127.0.0.1)
// Normally started by ./mock-http.sh start.
// ---------------------------------------------------------------------------

import { createServer } from 'node:http';

const portArg = process.argv.indexOf('--port');
const PORT = Number(portArg > 0 ? process.argv[portArg + 1] : process.env.MOCK_HTTP_PORT ?? 18481);

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
  res.end(text);
}

createServer((req, res) => {
  const path = (req.url ?? '').split('?')[0];
  if (path !== '/get') return send(res, 404, { error: 'not found' });
  if (req.method !== 'GET') return send(res, 405, { error: 'method not allowed' });
  const host = req.headers.host ?? '';
  send(res, 200, { url: `http://${host}/get`, headers: { Host: host } });
}).listen(PORT, '127.0.0.1');
