// Runs `npm audit` and fails on any high or critical advisory, except the
// narrow allowlist below. Everything else behaves like
// `npm audit --audit-level=high`.
import { spawnSync } from "node:child_process";

// Each entry must say why it is safe and when to remove it.
const ALLOWED = {
  // braces <= 3.0.3 (stack exhaustion on deeply nested patterns). No patched
  // release exists upstream (3.0.3 is the latest). It is reached only through
  // eslint-config-next > @next/eslint-plugin-next > fast-glob > micromatch,
  // which is dev-only lint tooling that globs our own source tree, never
  // untrusted input, and is not shipped in the app. Remove this entry once
  // braces publishes a fix.
  "GHSA-vfj7-8cjw-p6xm": "braces: dev-only lint dependency, no patch available",
};

const result = spawnSync("npm", ["audit", "--json"], {
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});
let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  console.error("Could not parse npm audit output:\n" + result.stdout + result.stderr);
  process.exit(1);
}
if (report.error) {
  console.error("npm audit failed: " + JSON.stringify(report.error));
  process.exit(1);
}

const failing = new Map();
const skipped = new Set();
for (const [name, vuln] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of vuln.via) {
    if (typeof via === "string") continue;
    if (via.severity !== "high" && via.severity !== "critical") continue;
    const id = via.url.split("/").pop();
    if (id in ALLOWED) {
      skipped.add(`${id} (${ALLOWED[id]})`);
    } else {
      failing.set(id, `${name}: ${via.title} [${via.severity}] ${via.url}`);
    }
  }
}

for (const note of skipped) console.log(`allowed: ${note}`);
if (failing.size > 0) {
  for (const line of failing.values()) console.error(`FAIL ${line}`);
  process.exit(1);
}
console.log("npm audit: no high or critical advisories outside the allowlist");
