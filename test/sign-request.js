// Worker-side signer, kept here so the test suite can exercise the real
// wire format end-to-end -- the ACTUAL sign implementation this repo cares
// about lives in TheEmpireGroupMCP (the Worker); this is a test-only mirror
// of the same, tiny, fully-specified algorithm (doc 19's "Closing B3"). If
// TheEmpireGroupMCP's real signer ever diverges from this shape, this test
// suite verifying against ITS OWN mirror won't catch that -- the actual
// cross-repo contract test is the integration script in scripts/, which
// signs with a real keypair and hits the real deployed function.
import { base64urlEncode, utf8Encode } from '../supabase/functions/_shared/base64url.js';

const ALG = 'ES256';
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };

export async function signRelayRequest(privateKeyJwk, rawBodyBytes, claims) {
  const { iss, aud, contractVersion, ttlSeconds = 5 } = claims;
  const header = { alg: ALG, typ: 'JWT' };
  const hashBuf = await crypto.subtle.digest('SHA-256', rawBodyBytes);
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
