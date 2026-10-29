// Regenerates src/data.generated.json, the only source of the video's data:
//   - the claims shown on screen, copied from ../eval/claims.json by claim_id
//   - the terminal replay: line ranges of assets/scan_output.txt (the real
//     `gittrace scan` stdout), copied verbatim, in order
//   - the call path: one real route -> handler -> ... -> sink path from
//     assets/scan_result.json (the same scan, --format json)
//   - the install command: the README's `pipx install git+...` line
// Nothing here is typed by hand: change the sources and rerun.
//
//   node scripts/build-data.mjs           write src/data.generated.json
//   node scripts/build-data.mjs --check   exit 1 if it is out of date

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const promo = join(here, "..");
const repo = join(promo, "..");
const read = (p) => readFileSync(p, "utf8").replace(/\r\n/g, "\n");

// The claims the video states, by claim_id (eval/claims.json).
export const SHOWN = {
  reachUntouched: "eval-reach-untouched",
  reachLater: "eval-reach-after-reachability",
  unauthUntouched: "eval-unauth-untouched",
  unauthLater: "eval-unauth-after-reachability",
};

// The scan the terminal scene replays, and the route whose path is drawn.
export const SCAN = {
  command: "gittrace scan bad --no-llm --no-blame --fail-on none",
  cwd: "a checkout of fportantier/vulpy (eval target vulpy-bad)",
  finding: "libuser.py::12::12",
  route: "GET /user/login -> mod_user.py::do_login",
};

export function build() {
  const claims = JSON.parse(read(join(repo, "eval", "claims.json"))).claims;
  const byId = Object.fromEntries(claims.map((c) => [c.claim_id, c]));
  const shown = {};
  for (const [key, id] of Object.entries(SHOWN)) {
    const c = byId[id];
    if (!c) throw new Error(`claim ${id} is not in eval/claims.json`);
    shown[key] = {
      claim_id: c.claim_id, label: c.label, dimension: c.dimension,
      marked: c.marked, wrong: c.wrong, source_file: c.source_file,
    };
  }

  const lines = read(join(promo, "assets", "scan_output.txt")).split("\n");
  const fourth = lines.findIndex((l) => l.startsWith("4. "));
  if (fourth < 0) throw new Error("scan_output.txt: no finding 4 in the list");
  const summary = lines.slice(0, fourth);                          // header panel + findings 1-3, as printed
  const start = lines.findIndex((l) => l.includes("Attack paths"));
  const end = lines.findIndex((l, i) => i > start && l.includes("c.execute  at"));
  const attack = lines.slice(start, end + 1);                      // finding 1's first attack path

  const scan = JSON.parse(read(join(promo, "assets", "scan_result.json")));
  const finding = scan.findings.find((f) => f.id === SCAN.finding);
  const route = finding.reachability.routes.find((r) => r.endpoint === SCAN.route);
  const path = {
    endpoint: `${route.method} ${route.path}`,
    auth_required: route.auth_required,
    functions: route.path_nodes.slice(1),                          // handler ... vulnerable function
    sink: `${finding.callee}`,
    sink_at: `${finding.location.file}:${finding.location.line}`,
    rule: finding.title,
  };

  const install = read(join(repo, "README.md")).split("\n")
    .find((l) => l.startsWith("pipx install git+"))
    .split("#")[0].trim();

  return {
    generated_from: {
      claims: "eval/claims.json",
      scan_output: "promo/assets/scan_output.txt",
      scan_result: "promo/assets/scan_result.json",
      install: "README.md",
    },
    claims: shown,
    terminal: { command: SCAN.command, summary, attack },
    path,
    install,
    repo_url: "github.com/codingwinterz/GitTrace",
  };
}

const target = join(promo, "src", "data.generated.json");
const text = JSON.stringify(build(), null, 1) + "\n";
if (process.argv.includes("--check")) {
  const current = (() => { try { return read(target); } catch { return ""; } })();
  if (current !== text) {
    console.error("src/data.generated.json is out of date: run `npm run data`");
    process.exit(1);
  }
  console.log("src/data.generated.json is up to date");
} else {
  writeFileSync(target, text);
  console.log("wrote src/data.generated.json");
}
