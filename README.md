# mcp-postgres-relay

Supabase Edge Function relay giving `TheEmpireGroupMCP`'s per-principal Postgres connections real
TLS — see that repo's `docs/planning/19-postgres-tls-via-supabase-edge-function.md` and
`docs/planning/20-implementation-plan-postgres-tls-relay.md` for the full design, two independent
review rounds, and build plan.

**Status: `mcp-query-relay` is the real implementation** (JWT verification, `sql.begin()`-pinned
query execution, `pg-plan-guard`-based cross-schema safety, error mapping) — not yet wired to
`TheEmpireGroupMCP`'s Worker side (that's Step 3 in doc 20, tracked separately) and not yet
cut over in production.

## Auth model (see `docs/planning/19`'s closed B3 for the full reasoning)

Two independent layers, deliberately in two different headers so they never fight each other:

- **`Authorization: Bearer <supabase-anon-key>`** — Supabase's own platform `verify_jwt` gate,
  left on as outer defense-in-depth.
- **`X-Relay-Auth: Bearer <jws>`** — this design's own scheme. ES256-signed (algorithm pinned,
  never read from the token header), short-lived (~5s), binds the exact request body via a
  `payload_hash` claim (raw bytes, never a re-serialized/canonicalized form). See
  `supabase/functions/_shared/verify-request.js`.

## Testing

```bash
npm test                              # local, no network -- the full JWT verification suite
node scripts/verify-relay-live.mjs    # against a real deployed instance, see that file's header
```

## One-time setup needed before CI can deploy

1. ✅ An org owner adds this repo to `@mp4marketing/pg-plan-guard`'s "Manage Actions access"
   allowlist (package settings on GitHub — no public API for this).
2. Repo secrets: `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_REF`.
3. Supabase project secrets (`supabase secrets set`): `RELAY_CURRENT_PUBLIC_KEY_JWK` (and
   `RELAY_PREVIOUS_PUBLIC_KEY_JWK` once a rotation has happened). The matching private key lives as
   `MCP_RELAY_SIGNING_PRIVATE_KEY_JWK` on `TheEmpireGroupMCP`'s own Worker (`wrangler secret put`) —
   never in this repo.
