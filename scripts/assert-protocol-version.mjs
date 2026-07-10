#!/usr/bin/env node
// Assert that the mcpglass gateway recorded a negotiated MCP protocol version for
// at least one session in its SQLite store. This is the observability half of the
// conformance gate: passing the suite proves the proxy is transparent on the wire;
// this proves it also *observed* the version handshake it forwarded.
//
// Usage:  node --experimental-sqlite scripts/assert-protocol-version.mjs <db-path>
//
// (The `--experimental-sqlite` flag is required on Node 22.x; on Node >=23.4 the
// built-in `node:sqlite` module is available without it, and the flag is ignored.)
//
// Exit codes: 0 = at least one session has a non-NULL protocol_version; 1 = none
// (or the db/table is missing / unreadable).

import { DatabaseSync } from 'node:sqlite';

const dbPath = process.argv[2];
if (!dbPath) {
  console.error('assert-protocol-version: missing <db-path> argument');
  process.exit(1);
}

let db;
try {
  db = new DatabaseSync(dbPath, { readOnly: true });
} catch (err) {
  console.error(`assert-protocol-version: cannot open ${dbPath}: ${err.message}`);
  process.exit(1);
}

try {
  const { c } = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE protocol_version IS NOT NULL').get();
  const total = db.prepare('SELECT COUNT(*) AS c FROM sessions').get().c;
  console.log(`sessions: ${total} total, ${c} with a recorded protocol_version`);
  if (c > 0) {
    const sample = db
      .prepare('SELECT protocol_version, client_protocol_version, protocol_version_source FROM sessions WHERE protocol_version IS NOT NULL LIMIT 3')
      .all();
    for (const s of sample) {
      console.log(`  negotiated=${s.protocol_version} proposed=${s.client_protocol_version} source=${s.protocol_version_source}`);
    }
    process.exit(0);
  }
  console.error('assert-protocol-version: FAIL — no session recorded a protocol_version');
  process.exit(1);
} catch (err) {
  console.error(`assert-protocol-version: query failed: ${err.message}`);
  process.exit(1);
}
