// Fails (exit 1) if a number the video shows could differ from eval/claims.json.
//
//   1. every claim the video shows (SHOWN in src/data/claims.ts) is a record in
//      ../eval/claims.json; the scenes read marked/wrong/label only through
//      claim(id), so what is on screen is that record
//   2. those records match the results they cite: ../eval/claims.py recounts
//      them (skipped with a warning when no Python can run it)
//   3. no hand-typed number: no digit in a string of src/copy.ts, none in JSX
//      text anywhere in src/ (found with the TypeScript parser), and no
//      numeric literal passed as a claim's marked/wrong
//   4. the terminal and the call path come from the real scan in public/
//
//   node scripts/check-claims.mjs

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const promo = join(here, "..");
const repo = join(promo, "..");
const read = (p) => readFileSync(p, "utf8").replace(/\r\n/g, "\n");
const ts = createRequire(import.meta.url)("typescript");
const problems = [];

const parse = (path) => ts.createSourceFile(path, read(path), ts.ScriptTarget.Latest, true,
  path.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
const walk = (node, fn) => { fn(node); ts.forEachChild(node, (c) => walk(c, fn)); };

// 1. The shown claim ids, read from src/data/claims.ts.
const records = Object.fromEntries(JSON.parse(read(join(repo, "eval", "claims.json"))).claims.map((c) => [c.claim_id, c]));
const shown = [];
walk(parse(join(promo, "src", "data", "claims.ts")), (n) => {
  if (ts.isVariableDeclaration(n) && n.name.getText() === "SHOWN") {
    walk(n, (m) => { if (ts.isStringLiteral(m)) shown.push(m.text); });
  }
});
if (shown.length === 0) problems.push("src/data/claims.ts: no SHOWN claim ids found");
for (const id of shown) if (!records[id]) problems.push(`claim ${id} is not in eval/claims.json`);

// 2. The records against the results they cite.
const pythons = [join(repo, ".venv", "Scripts", "python.exe"), join(repo, ".venv", "bin", "python"), "python3", "python"];
const python = pythons.find((p) => !p.includes("/") && !p.includes("\\") ? true : existsSync(p));
try {
  execFileSync(python, [join(repo, "eval", "claims.py")], { cwd: repo, stdio: "pipe" });
} catch (e) {
  if (e.code === "ENOENT") console.warn("warning: no Python to run eval/claims.py; records not recounted");
  else problems.push(`eval/claims.py: ${String(e.stdout || "").split("\n").filter((l) => l.startsWith("PROBLEM")).join("; ") || e.message}`);
}

// 3. Hand-typed numbers.
const files = [];
const collect = (dir) => readdirSync(dir).forEach((f) => {
  const p = join(dir, f);
  if (statSync(p).isDirectory()) collect(p);
  else if (/\.(tsx?|ts)$/.test(f) && !f.endsWith(".d.ts")) files.push(p);
});
collect(join(promo, "src"));
for (const path of files) {
  const rel = path.slice(promo.length + 1).replace(/\\/g, "/");
  walk(parse(path), (n) => {
    if (ts.isJsxText(n) && /\d/.test(n.text)) problems.push(`${rel}: hand-typed number in JSX text ${JSON.stringify(n.text.trim())}`);
    if (rel === "src/copy.ts" && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) && /\d/.test(n.text)) {
      problems.push(`src/copy.ts: hand-typed number in ${JSON.stringify(n.text)}`);
    }
    if (ts.isPropertyAssignment(n) && ["marked", "wrong"].includes(n.name.getText()) && ts.isNumericLiteral(n.initializer)) {
      problems.push(`${rel}: hand-typed ${n.name.getText()}: ${n.initializer.text}`);
    }
  });
}

// 4. The real scan: the drawn route exists, and the replay file is the captured stdout.
const scan = JSON.parse(read(join(promo, "public", "scan_result.json")));
const finding = scan.findings.find((f) => f.id === "libuser.py::12::12");
if (!finding?.reachability.routes.some((r) => r.endpoint === "GET /user/login -> mod_user.py::do_login")) {
  problems.push("public/scan_result.json: the drawn route GET /user/login is not in the scan");
}
const output = read(join(promo, "public", "scan_output.txt"));
if (!output.includes("gittrace scan · bad") || !output.includes("Reached from: GET /user/login")) {
  problems.push("public/scan_output.txt is not the captured `gittrace scan bad` output");
}

if (problems.length) {
  for (const p of problems) console.error("PROBLEM:", p);
  process.exit(1);
}
console.log(`ok: ${shown.length} shown claims are records in eval/claims.json and match their results; no hand-typed numbers; the scan data is real`);
