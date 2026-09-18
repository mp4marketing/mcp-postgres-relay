# mcp-postgres-relay

Supabase Edge Function relay giving `TheEmpireGroupMCP`'s per-principal Postgres connections real
TLS — see that repo's `docs/planning/19-postgres-tls-via-supabase-edge-function.md` and
`docs/planning/20-implementation-plan-postgres-tls-relay.md` for the full design and build plan.

**Status: probe stage.** `supabase/functions/mcp-query-relay/index.ts` currently only proves that
`@mp4marketing/pg-plan-guard` (a private GitHub Package) resolves correctly through Deno's `npm:`
specifier inside a real CI-driven Supabase Edge Function deploy — the actual relay logic (JWT
verification, `sql.begin()`-pinned query execution, error mapping) isn't built yet.

## One-time setup needed before CI can deploy

1. An org owner adds this repo to `@mp4marketing/pg-plan-guard`'s "Manage Actions access" allowlist
   (package settings on GitHub — no public API for this, per this org's root `CLAUDE.md`).
2. Repo secrets: `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_REF`.
