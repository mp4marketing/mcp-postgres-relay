import assert from 'node:assert/strict';
import { test } from 'node:test';
import { signRelayRequest } from './sign-request.js';
import { verifyRelayRequest, RelayAuthError } from '../supabase/functions/_shared/verify-request.js';
import { base64urlEncode, utf8Encode } from '../supabase/functions/_shared/base64url.js';

const ISS = 'the-empire-group-mcp';
const AUD = 'mcp-postgres-relay';
const CONTRACT_VERSION = 1;

async function generateKeypair() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { privateKeyJwk: await crypto.subtle.exportKey('jwk', kp.privateKey), publicKeyJwk: await crypto.subtle.exportKey('jwk', kp.publicKey) };
}

const body = JSON.stringify({ role: 'mcp_principal_' + 'a'.repeat(32), password: 'x', database: 'crm', sql: 'SELECT 1', params: [] });

test('valid request verifies and returns claims', async () => {
  const { privateKeyJwk, publicKeyJwk } = await generateKeypair();
  const jwt = await signRelayRequest(privateKeyJwk, utf8Encode(body), { iss: ISS, aud: AUD, contractVersion: CONTRACT_VERSION });
  const claims = await verifyRelayRequest(body, `Bearer ${jwt}`, {
    currentPublicKeyJwk: publicKeyJwk,
    expectedIss: ISS,
    expectedAud: AUD,
    expectedContractVersion: CONTRACT_VERSION,
  });
  assert.equal(claims.iss, ISS);
});

test('rejects alg:none forgery attempt', async () => {
  const { publicKeyJwk } = await generateKeypair();
  const header = base64urlEncode(utf8Encode(JSON.stringify({ alg: 'none', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const hash = base64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(body))));
  const payload = base64urlEncode(utf8Encode(JSON.stringify({ payload_hash: hash, iat: now, exp: now + 5, iss: ISS, aud: AUD, contract_version: CONTRACT_VERSION })));
  const forgedJwt = `${header}.${payload}.`;
  await assert.rejects(
    () => verifyRelayRequest(body, `Bearer ${forgedJwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'auth_bad_alg'
  );
});

test('rejects alg:HS256 forgery using the "public" key bytes as an HMAC secret', async () => {
  const { publicKeyJwk } = await generateKeypair();
  const header = base64urlEncode(utf8Encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const hash = base64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(body))));
  const payload = base64urlEncode(utf8Encode(JSON.stringify({ payload_hash: hash, iat: now, exp: now + 5, iss: ISS, aud: AUD, contract_version: CONTRACT_VERSION })));
  const signingInput = `${header}.${payload}`;
  const hmacKey = await crypto.subtle.importKey('raw', utf8Encode(JSON.stringify(publicKeyJwk)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const forgedSig = base64urlEncode(new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, utf8Encode(signingInput))));
  const forgedJwt = `${signingInput}.${forgedSig}`;
  await assert.rejects(
    () => verifyRelayRequest(body, `Bearer ${forgedJwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'auth_bad_alg'
  );
});

test('rejects a tampered body (payload_hash mismatch)', async () => {
  const { privateKeyJwk, publicKeyJwk } = await generateKeypair();
  const jwt = await signRelayRequest(privateKeyJwk, utf8Encode(body), { iss: ISS, aud: AUD, contractVersion: CONTRACT_VERSION });
  const tamperedBody = JSON.stringify({ ...JSON.parse(body), sql: 'DROP TABLE crm.contacts' });
  await assert.rejects(
    () => verifyRelayRequest(tamperedBody, `Bearer ${jwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'payload_hash_mismatch'
  );
});

test('rejects an expired token', async () => {
  const { privateKeyJwk, publicKeyJwk } = await generateKeypair();
  const jwt = await signRelayRequest(privateKeyJwk, utf8Encode(body), { iss: ISS, aud: AUD, contractVersion: CONTRACT_VERSION, ttlSeconds: -1 });
  await assert.rejects(
    () => verifyRelayRequest(body, `Bearer ${jwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'auth_expired'
  );
});

test('rejects wrong audience', async () => {
  const { privateKeyJwk, publicKeyJwk } = await generateKeypair();
  const jwt = await signRelayRequest(privateKeyJwk, utf8Encode(body), { iss: ISS, aud: 'someone-else', contractVersion: CONTRACT_VERSION });
  await assert.rejects(
    () => verifyRelayRequest(body, `Bearer ${jwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'auth_bad_audience'
  );
});

test('rejects signature from a DIFFERENT keypair (not the trusted one)', async () => {
  const { publicKeyJwk } = await generateKeypair();
  const attacker = await generateKeypair();
  const jwt = await signRelayRequest(attacker.privateKeyJwk, utf8Encode(body), { iss: ISS, aud: AUD, contractVersion: CONTRACT_VERSION });
  await assert.rejects(
    () => verifyRelayRequest(body, `Bearer ${jwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'auth_bad_signature'
  );
});

test('accepts signature from the PREVIOUS key during a rotation window', async () => {
  const previous = await generateKeypair();
  const current = await generateKeypair();
  const jwt = await signRelayRequest(previous.privateKeyJwk, utf8Encode(body), { iss: ISS, aud: AUD, contractVersion: CONTRACT_VERSION });
  const claims = await verifyRelayRequest(body, `Bearer ${jwt}`, {
    currentPublicKeyJwk: current.publicKeyJwk,
    previousPublicKeyJwk: previous.publicKeyJwk,
    expectedIss: ISS,
    expectedAud: AUD,
    expectedContractVersion: CONTRACT_VERSION,
  });
  assert.equal(claims.iss, ISS);
});

test('rejects a contract_version mismatch', async () => {
  const { privateKeyJwk, publicKeyJwk } = await generateKeypair();
  const jwt = await signRelayRequest(privateKeyJwk, utf8Encode(body), { iss: ISS, aud: AUD, contractVersion: 999 });
  await assert.rejects(
    () => verifyRelayRequest(body, `Bearer ${jwt}`, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'contract_version_mismatch'
  );
});

test('rejects a missing Authorization header', async () => {
  const { publicKeyJwk } = await generateKeypair();
  await assert.rejects(
    () => verifyRelayRequest(body, null, { currentPublicKeyJwk: publicKeyJwk, expectedIss: ISS, expectedAud: AUD, expectedContractVersion: CONTRACT_VERSION }),
    (err) => err instanceof RelayAuthError && err.safeCategory === 'auth_missing'
  );
});
