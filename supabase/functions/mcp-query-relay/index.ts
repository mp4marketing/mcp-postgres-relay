// The real relay -- see TheEmpireGroupMCP's docs/planning/19 and 20 for the
// full design and review history. This function is intentionally a
// "mechanical relay": it holds no authorization logic of its own beyond
// re-validating the shapes the Worker already validated (never trusting
// "the Worker already checked this," since this endpoint is reachable
// independent of the Worker -- doc 19's closed B3).
//
// HARD RULE, enforced by review, not just convention: never log the request
// body, the Postgres connection string/options, or any error object that
// could serialize either. A single debug console.log here ships every
// principal's live password into Supabase's platform log store.
import postgres from "npm:postgres@3.4.4";
import {
  assertPlanStaysWithinSchema,
  SCHEMA_NAME_PATTERN,
  PRINCIPAL_ROLE_PATTERN,
  MAX_RESPONSE_BYTES,
} from "npm:@mp4marketing/pg-plan-guard@0.1.0";
import { verifyRelayRequest, RelayAuthError } from "../_shared/verify-request.js";

const CONTRACT_VERSION = 1;
const EXPECTED_ISS = "the-empire-group-mcp";
const EXPECTED_AUD = "mcp-postgres-relay";

// Strictly below the Worker's own fetch AbortSignal timeout and the
// platform's 120s statement_timeout -- doc 19's fetch-timeout note.
const INTERNAL_TIMEOUT_MS = 20_000;
const SQL_END_TIMEOUT_S = 2;

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function errorResponse(safeCategory: string, safeReason: string, status = 400, code?: string) {
  return jsonResponse({ ok: false, safeCategory, safeReason, code: code ?? null }, status);
}

const FIXED_REASONS: Record<string, string> = {
  auth_missing: "Authentication failed.",
  auth_malformed: "Authentication failed.",
  auth_bad_alg: "Authentication failed.",
  auth_bad_signature: "Authentication failed.",
  auth_bad_audience: "Authentication failed.",
  auth_expired: "Authentication failed. Request expired -- retry.",
  contract_version_mismatch: "Relay contract version mismatch -- redeploy required.",
  payload_hash_mismatch: "Request integrity check failed.",
  invalid_role: "The requested principal role failed safety validation.",
  invalid_database: "The requested schema failed safety validation.",
  response_too_large: "The result was too large to return.",
  relay_timeout: "The query could not be planned. It likely has a syntax or structural error.",
};

async function withTimeout<T>(promise: Promise<T>, ms: number, category: string): Promise<T> {
  let timer: number;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error("relay timeout"), { safeCategory: category })), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") {
    return errorResponse("method_not_allowed", "Method not allowed.", 405);
  }

  const rawBodyText = await req.text();

  let claims;
  try {
    claims = await verifyRelayRequest(rawBodyText, req.headers.get("x-relay-auth"), {
      currentPublicKeyJwk: JSON.parse(Deno.env.get("RELAY_CURRENT_PUBLIC_KEY_JWK")!),
      previousPublicKeyJwk: Deno.env.get("RELAY_PREVIOUS_PUBLIC_KEY_JWK")
        ? JSON.parse(Deno.env.get("RELAY_PREVIOUS_PUBLIC_KEY_JWK")!)
        : null,
      expectedIss: EXPECTED_ISS,
      expectedAud: EXPECTED_AUD,
      expectedContractVersion: CONTRACT_VERSION,
    });
  } catch (e) {
    if (e instanceof RelayAuthError) {
      return errorResponse(e.safeCategory, FIXED_REASONS[e.safeCategory] ?? "Authentication failed.", 401);
    }
    return errorResponse("auth_malformed", "Authentication failed.", 401);
  }
  void claims; // verified, not otherwise needed below

  let role: string, password: string, database: string, sql: string, params: unknown[];
  try {
    ({ role, password, database, sql, params } = JSON.parse(rawBodyText));
  } catch {
    return errorResponse("auth_malformed", "Authentication failed.", 400);
  }

  // Re-validate independently -- never trust "the Worker already checked
  // this" (doc 19, closed B3).
  if (typeof role !== "string" || !PRINCIPAL_ROLE_PATTERN.test(role)) {
    return errorResponse("invalid_role", FIXED_REASONS.invalid_role, 400);
  }
  if (typeof database !== "string" || !SCHEMA_NAME_PATTERN.test(database)) {
    return errorResponse("invalid_database", FIXED_REASONS.invalid_database, 400);
  }
  if (!Array.isArray(params) || params.length === 0) {
    // doc 19 round-2 SF-6: caller-derived SQL must always use the extended
    // protocol (non-empty params) -- never the simple protocol, which can
    // execute `;`-separated multiple statements.
    return errorResponse("invalid_protocol", "Query must use the parameterized protocol.", 400);
  }

  // Fresh client per request -- NEVER module scope (doc 19 closed B2: a
  // reused Deno isolate must never let one principal's request run on a
  // connection authenticated as a different principal).
  const client = postgres({
    host: "db.svjemxaceebvuutpoixk.supabase.co",
    port: 5432,
    database: "postgres",
    username: role,
    password,
    ssl: "require",
    max: 1,
    connect_timeout: 8,
    // Auto-reconnect must never turn one bad/rotated credential into a
    // reconnect storm against max_connections (doc 19 round-1 S1).
    connection: { application_name: "mcp-postgres-relay" },
  });

  try {
    const result = await withTimeout(
      client.begin(async (txSql) => {
        // Same physical connection for the whole sequence, by construction
        // (doc 19 closed B1) -- always the callback's own (shadowed) txSql,
        // never the outer `client`.
        await txSql.unsafe(`SET LOCAL search_path = ${database}`);
        const txRunQuery = (text: string, queryParams: unknown[]) => txSql.unsafe(text, queryParams as never);
        await assertPlanStaysWithinSchema(txRunQuery, sql, params, database);
        return await txSql.unsafe(sql, params as never);
      }),
      INTERNAL_TIMEOUT_MS,
      "relay_timeout"
    );

    const rows = Array.from(result as unknown as Iterable<Record<string, unknown>>);
    const payload = JSON.stringify({ ok: true, rows });
    if (new TextEncoder().encode(payload).length > MAX_RESPONSE_BYTES) {
      return errorResponse("response_too_large", FIXED_REASONS.response_too_large, 413);
    }
    return new Response(payload, { headers: { "content-type": "application/json" } });
  } catch (e: unknown) {
    const err = e as { safeCategory?: string; code?: string; message?: string };
    if (err && err.safeCategory) {
      // pg-plan-guard's own throws, or our relay-timeout marker -- fixed
      // categories only, never echo err.message as safeReason (doc 19 S5:
      // safeReason is always a fixed string, never an interpolation site).
      return errorResponse(err.safeCategory, FIXED_REASONS[err.safeCategory] ?? "The query could not be completed.", 500);
    }
    // Real Postgres errors: pass the raw SQLSTATE code through, no message.
    return errorResponse("query_failed", "The query could not be completed.", 500, err?.code);
  } finally {
    // NOT a bare `sql.end()` -- that waits indefinitely for in-flight
    // queries instead of closing (doc 19 closed B2's cleanup correction).
    await client.end({ timeout: SQL_END_TIMEOUT_S }).catch(() => {});
  }
});
