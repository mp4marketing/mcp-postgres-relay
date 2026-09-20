// Doc 20 Step 4 -- pre-cutover measurement. Re-measures p50 latency and a
// concurrency burst (10/20/40) against the FINAL relay shape (fresh client,
// max:1, sql.begin(), sql.end({timeout}), direct endpoint) -- the earlier
// "~2.3s" number in doc 19 predates all of B1/B2's discipline and doesn't
// carry over. Needs the same env as verify-relay-live.mjs.
import { callRelay } from './sign-request.mjs';

const RELAY_URL = process.env.RELAY_URL;
const ROLE_A = process.env.ROLE_A;
const PASSWORD_A = process.env.PASSWORD_A;

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function timedCall() {
  const start = performance.now();
  const { status, json } = await callRelay(RELAY_URL, {
    role: ROLE_A,
    password: PASSWORD_A,
    database: 'crm',
    sql: 'SELECT current_user AS u FROM crm.accounts LIMIT $1',
    params: [1],
  });
  const elapsed = performance.now() - start;
  return { elapsed, ok: status === 200 && json.rows?.[0]?.u === ROLE_A };
}

async function sequentialRun(n) {
  const timings = [];
  for (let i = 0; i < n; i++) {
    const { elapsed, ok } = await timedCall();
    if (!ok) console.error(`  sequential call ${i} FAILED`);
    timings.push(elapsed);
  }
  return timings;
}

async function burst(n) {
  const start = performance.now();
  const results = await Promise.allSettled(Array.from({ length: n }, () => timedCall()));
  const wallMs = performance.now() - start;
  const succeeded = results.filter((r) => r.status === 'fulfilled' && r.value.ok).length;
  const failed = n - succeeded;
  const timings = results.filter((r) => r.status === 'fulfilled').map((r) => r.value.elapsed).sort((a, b) => a - b);
  return { n, succeeded, failed, wallMs, timings };
}

console.log(`=== Sequential (p50 baseline), 20 calls, against ${RELAY_URL} ===`);
const seq = (await sequentialRun(20)).sort((a, b) => a - b);
console.log(`p50: ${percentile(seq, 50).toFixed(0)}ms  p90: ${percentile(seq, 90).toFixed(0)}ms  min: ${seq[0].toFixed(0)}ms  max: ${seq[seq.length - 1].toFixed(0)}ms`);

for (const n of [10, 20, 40]) {
  console.log(`\n=== Concurrency burst: ${n} ===`);
  const { succeeded, failed, wallMs, timings } = await burst(n);
  console.log(`succeeded: ${succeeded}/${n}  failed: ${failed}  wall time: ${wallMs.toFixed(0)}ms`);
  if (timings.length > 0) {
    console.log(`p50: ${percentile(timings, 50).toFixed(0)}ms  p90: ${percentile(timings, 90).toFixed(0)}ms  max: ${timings[timings.length - 1].toFixed(0)}ms`);
  }
  // brief pause between bursts so pg_stat_activity checks (run separately) see a clean baseline
  await new Promise((r) => setTimeout(r, 2000));
}
