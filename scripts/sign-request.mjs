// Shared by every verify-*.mjs script below -- signs a request the exact
// way TheEmpireGroupMCP's Worker will, using the SAME algorithm/claim shape
// as supabase/functions/_shared/verify-request.js expects. Requires
// RELAY_PRIVATE_KEY_JWK (JSON string) in the environment -- never pass it
// as a CLI argument (would land in shell history / process list).
import { base64urlEncode, utf8Encode } from '../supabase/functions/_shared/base64url.js';

const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };

export async function signRequest(bodyText, { iss = 'the-empire-group-mcp', aud = 'mcp-postgres-relay', contractVersion = 1, ttlSeconds = 5 } = {}) {
  const privateKeyJwk = JSON.parse(process.env.RELAY_PRIVATE_KEY_JWK);
  const header = { alg: 'ES256', typ: 'JWT' };
  const hashBuf = await crypto.subtle.digest('SHA-256', utf8Encode(bodyText));
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    payload_hash: base64urlEncode(new Uint8Array(hashBuf)),
    iat: now,
    exp: now + ttlSeconds,
    iss,
    aud,
    contract_version: contractVersion,
  };
  const signingInput = `${base64urlEncode(utf8Encode(JSON.stringify(header)))}.${base64urlEncode(utf8Encode(JSON.stringify(payload)))}`;
  const key = await crypto.subtle.importKey('jwk', privateKeyJwk, ECDSA_PARAMS, false, ['sign']);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8Encode(signingInput));
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`;
}

export async function callRelay(relayUrl, { role, password, database, sql, params }) {
  const body = JSON.stringify({ role, password, database, sql, params });
  const jwt = await signRequest(body);
  // `authorization` here is Supabase's OWN publishable/anon key -- satisfies
  // the platform verify_jwt gate (left ON, doc 19). `x-relay-auth` is this
  // design's own scheme, verified independently in application code. The
  // two never share a header -- see verify-request.js's own header comment.
  const res = await fetch(relayUrl, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${process.env.SUPABASE_ANON_KEY}`,
      'x-relay-auth': `Bearer ${jwt}`,
      'content-type': 'application/json',
    },
    body,
  });
  return { status: res.status, json: await res.json() };
}
