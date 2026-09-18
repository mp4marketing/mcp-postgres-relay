// PROBE STAGE: this function currently only proves that a private
// GitHub-Packages npm module resolves correctly through Deno's `npm:`
// specifier inside a real Supabase Edge Function deploy, driven by CI (no
// personal token ever handled outside GitHub's own infrastructure). Once
// that's confirmed, this becomes the real relay per
// TheEmpireGroupMCP/docs/planning/19 and 20.
import {
  SCHEMA_NAME_PATTERN,
  PRINCIPAL_ROLE_PATTERN,
  MAX_RESPONSE_BYTES,
} from "npm:@mp4marketing/pg-plan-guard@0.1.0";

Deno.serve(() => {
  return new Response(
    JSON.stringify({
      ok: true,
      importResolved: true,
      schemaPatternWorks: SCHEMA_NAME_PATTERN.test("crm") && !SCHEMA_NAME_PATTERN.test("4crm"),
      rolePatternWorks: PRINCIPAL_ROLE_PATTERN.test("mcp_principal_" + "a".repeat(32)),
      maxResponseBytes: MAX_RESPONSE_BYTES,
    }),
    { headers: { "content-type": "application/json" } },
  );
});
