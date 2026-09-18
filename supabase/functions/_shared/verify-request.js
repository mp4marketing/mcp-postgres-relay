// Edge-Function-side: verifies the signed envelope for one
// mcp-postgres-relay call. Per doc 19's closed B3 -- this is the actual
// security boundary once the Edge Function is reachable at a public URL.
//
// Check order (doc 19, "Closing B3" -> "Check order"): signature first,
// then iss/aud, then payload-hash. Only after all three pass does the
// caller get to read anything from the body.
import { base64urlDecode, base64urlEncode, utf8Encode, utf8Decode } from './base64url.js';

const ALLOWED_ALG = 'ES256'; // hardcoded -- NEVER read from the token's own header to decide how to verify.
const ECDSA_PARAMS = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_VERIFY_PARAMS = { name: 'ECDSA', hash: 'SHA-256' };

class RelayAuthError extends Error {
  constructor(message, safeCategory) {
    super(message);
    this.safeCategory = safeCategory;
  }
}

function b64urlToJson(b64) {
  return JSON.parse(utf8Decode(base64urlDecode(b64)));
}

/**
 * @param {string} rawBodyText - the exact request body text, read via
 *   `await req.text()` BEFORE any JSON.parse -- never a re-serialized form.
 * @param {string | null} relayAuthHeader - the `X-Relay-Auth` header value,
 *   e.g. `Bearer <jws>`. Deliberately NOT the standard `Authorization`
 *   header -- that one is reserved for Supabase's own platform `verify_jwt`
 *   gate (left ON, per doc 19, as an outer defense-in-depth layer). The two
 *   schemes verify against different keys entirely and would fight each
 *   other if forced into the same header.
 * @param {{
 *   currentPublicKeyJwk: JsonWebKey,
 *   previousPublicKeyJwk?: JsonWebKey | null,
 *   expectedIss: string,
 *   expectedAud: string,
 *   expectedContractVersion: number,
 * }} config
 * @returns {Promise<Record<string, unknown>>} the verified JWT payload claims.
 * @throws {RelayAuthError} with a fixed `safeCategory`, never a caller-influenced message.
 */
export async function verifyRelayRequest(rawBodyText, relayAuthHeader, config) {
  const { currentPublicKeyJwk, previousPublicKeyJwk, expectedIss, expectedAud, expectedContractVersion } = config;

  if (!relayAuthHeader || !relayAuthHeader.startsWith('Bearer ')) {
    throw new RelayAuthError('missing bearer token', 'auth_missing');
  }
  const token = relayAuthHeader.slice('Bearer '.length);
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new RelayAuthError('malformed token', 'auth_malformed');
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  let header;
  try {
    header = b64urlToJson(headerB64);
  } catch {
    throw new RelayAuthError('malformed token header', 'auth_malformed');
  }

  // Algorithm pinning -- doc 19 B3, the exact hole round 2 found. Reject
  // ANYTHING other than the one hardcoded algorithm, including 'none' and
  // 'HS256' (which would let an attacker HMAC-sign using the "public key"
  // bytes this Edge Function treats as non-secret). Also reject unknown
  // critical header extensions (RFC 7515 'crit').
  if (header.alg !== ALLOWED_ALG) {
    throw new RelayAuthError(`rejected alg: ${typeof header.alg}`, 'auth_bad_alg');
  }
  if (header.crit) {
    throw new RelayAuthError('rejected: crit header present', 'auth_bad_alg');
  }

  const signingInput = utf8Encode(`${headerB64}.${payloadB64}`);
  const signature = base64urlDecode(signatureB64);

  const candidateKeys = [currentPublicKeyJwk, previousPublicKeyJwk].filter(Boolean);
  let verified = false;
  for (const jwk of candidateKeys) {
    const key = await crypto.subtle.importKey('jwk', jwk, ECDSA_PARAMS, false, ['verify']);
    // eslint-disable-next-line no-await-in-loop
    if (await crypto.subtle.verify(ECDSA_VERIFY_PARAMS, key, signature, signingInput)) {
      verified = true;
      break;
    }
  }
  if (!verified) {
    throw new RelayAuthError('signature verification failed', 'auth_bad_signature');
  }

  let payload;
  try {
    payload = b64urlToJson(payloadB64);
  } catch {
    throw new RelayAuthError('malformed token payload', 'auth_malformed');
  }

  // iss/aud checked immediately after signature verification (doc 19 round-2
  // ordering fix -- moved up from after a now-removed jti step).
  if (payload.iss !== expectedIss || payload.aud !== expectedAud) {
    throw new RelayAuthError('iss/aud mismatch', 'auth_bad_audience');
  }

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) {
    throw new RelayAuthError('token expired', 'auth_expired');
  }

  if (payload.contract_version !== expectedContractVersion) {
    throw new RelayAuthError('contract_version mismatch', 'contract_version_mismatch');
  }

  // Payload-hash binding, checked last: raw bytes of the ACTUAL received
  // body, never a re-serialized/canonicalized form -- there is nothing to
  // canonicalize, so nothing to drift on.
  const actualHash = base64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8Encode(rawBodyText))));
  if (actualHash !== payload.payload_hash) {
    throw new RelayAuthError('payload hash mismatch', 'payload_hash_mismatch');
  }

  return payload;
}

export { RelayAuthError };
