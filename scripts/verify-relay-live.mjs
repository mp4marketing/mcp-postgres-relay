// Live verification against a real deployed mcp-query-relay, per
// TheEmpireGroupMCP/docs/planning/20's Step 2 required-tests checklist.
// Needs: RELAY_URL, RELAY_PRIVATE_KEY_JWK (matching whatever public key the
// deployed function has as RELAY_CURRENT_PUBLIC_KEY_JWK), and TWO real
// throwaway Postgres roles for the cross-principal test (create/drop them
// yourself around this run -- this script does not manage Postgres roles).
//
//   RELAY_URL=https://<ref>.supabase.co/functions/v1/mcp-query-relay \
//   RELAY_PRIVATE_KEY_JWK='{...}' \
//   ROLE_A=zzrelaytest_a PASSWORD_A=... \
//   ROLE_B=zzrelaytest_b PASSWORD_B=... \
//   node scripts/verify-relay-live.mjs
import assert from 'node:assert/strict';
import { callRelay, signRequest } from './sign-request.mjs';

const RELAY_URL = process.env.RELAY_URL;
if (!RELAY_URL) throw new Error('RELAY_URL required');

let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   - ${name}`);
    passed++;
  } catch (e) {
    console.error(`FAIL - ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

await check('a valid same-schema query succeeds', async () => {
  const { status, json } = await callRelay(RELAY_URL, {
    role: process.env.ROLE_A,
    password: process.env.PASSWORD_A,
    database: 'crm',
    sql: 'SELECT current_user AS u, pg_backend_pid() AS pid',
    params: [1],
  });
  assert.equal(status, 200, JSON.stringify(json));
  assert.equal(json.rows[0].u, process.env.ROLE_A);
});

await check('a cross-schema query is rejected with cross_schema_rejected', async () => {
  const { status, json } = await callRelay(RELAY_URL, {
    role: process.env.ROLE_A,
    password: process.env.PASSWORD_A,
    database: 'crm',
    sql: 'SELECT * FROM quickbooks.customers LIMIT $1',
    params: [1],
  });
  assert.equal(status, 500);
  assert.equal(json.safeCategory, 'cross_schema_rejected');
});

await check('a request with empty params is rejected (protocol-injection backstop)', async () => {
  const body = JSON.stringify({ role: process.env.ROLE_A, password: process.env.PASSWORD_A, database: 'crm', sql: 'SELECT 1; DROP TABLE crm.contacts;', params: [] });
  const jwt = await signRequest(body);
  const res = await fetch(RELAY_URL, {
    method: 'POST',
    headers: { authorization: `Bearer ${process.env.SUPABASE_ANON_KEY}`, 'x-relay-auth': `Bearer ${jwt}`, 'content-type': 'application/json' },
    body,
  });
  const json = await res.json();
  assert.equal(res.status, 400);
  assert.equal(json.safeCategory, 'invalid_protocol');
});

await check('a tampered body is rejected regardless of a valid signature', async () => {
  const realBody = JSON.stringify({ role: process.env.ROLE_A, password: process.env.PASSWORD_A, database: 'crm', sql: 'SELECT 1', params: [1] });
  const jwt = await signRequest(realBody);
  const tamperedBody = JSON.stringify({ role: process.env.ROLE_A, password: process.env.PASSWORD_A, database: 'crm', sql: 'SELECT 2', params: [1] });
  const res = await fetch(RELAY_URL, {
    method: 'POST',
    headers: { authorization: `Bearer ${process.env.SUPABASE_ANON_KEY}`, 'x-relay-auth': `Bearer ${jwt}`, 'content-type': 'application/json' },
    body: tamperedBody,
  });
  const json = await res.json();
  assert.equal(res.status, 401);
  assert.equal(json.safeCategory, 'payload_hash_mismatch');
});

if (process.env.ROLE_B && process.env.PASSWORD_B) {
  await check('calling as principal A then B in immediate succession returns the correct, DIFFERENT current_user each time (no cross-principal connection reuse)', async () => {
    const a = await callRelay(RELAY_URL, { role: process.env.ROLE_A, password: process.env.PASSWORD_A, database: 'crm', sql: 'SELECT current_user AS u', params: [1] });
    const b = await callRelay(RELAY_URL, { role: process.env.ROLE_B, password: process.env.PASSWORD_B, database: 'crm', sql: 'SELECT current_user AS u', params: [1] });
    assert.equal(a.json.rows[0].u, process.env.ROLE_A);
    assert.equal(b.json.rows[0].u, process.env.ROLE_B);
    assert.notEqual(a.json.rows[0].u, b.json.rows[0].u);
  });
} else {
  console.log('skip - cross-principal isolation test (set ROLE_B/PASSWORD_B to run it)');
}

console.log(`\n${passed} check(s) passed.`);
