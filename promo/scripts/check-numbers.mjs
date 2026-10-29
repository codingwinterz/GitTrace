// Fails (exit 1) if any number the video shows does not come from a record
// in ../eval/claims.json, or if the terminal replay is not the real output.
//
//   1. src/data.generated.json is what build-data.mjs makes from the sources now
//   2. every claim the video shows equals its eval/claims.json record
//      (label, dimension, marked, wrong, source_file)
//   3. no hand-typed number: no digit in src/copy.ts, none in JSX text in src/
//   4. the terminal lines are contiguous, unedited runs of assets/scan_output.txt
//
//   node scripts/check-numbers.mjs

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const promo = join(here, "..");
const repo = join(promo, "..");
const read = (p) => readFileSync(p, "utf8").replace(/\r\n/g, "\n");
const problems = [];

try {
  execFileSync(process.execPath, [join(here, "build-data.mjs"), "--check"], { stdio: "pipe" });
} catch (e) {
  problems.push(String(e.stderr || e.message).trim());
}

const data = JSON.parse(read(join(promo, "src", "data.generated.json")));
const records = Object.fromEntries(JSON.parse(read(join(repo, "eval", "claims.json"))).claims.map((c) => [c.claim_id, c]));
for (const [key, shown] of Object.entries(data.claims)) {
  const r = records[shown.claim_id];
  if (!r) { problems.push(`${key}: claim ${shown.claim_id} is not in eval/claims.json`); continue; }
  for (const field of ["label", "dimension", "marked", "wrong", "source_file"]) {
    if (r[field] !== shown[field]) problems.push(`${key}: ${field} ${shown[field]} != eval/claims.json ${r[field]}`);
  }
}

// Hand-typed numbers: any digit in a string of src/copy.ts, or in JSX text in src/*.tsx
// (found with the TypeScript parser, so code and style values are not text).
const ts = createRequire(import.meta.url)("typescript");
const visit = (file, node, out) => {
  if (ts.isJsxText(node) && /\d/.test(node.text)) out.push(`src/${file}: hand-typed number in JSX text ${JSON.stringify(node.text.trim())}`);
  if (file === "copy.ts" && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && /\d/.test(node.text)) {
    out.push(`src/copy.ts: hand-typed number in ${JSON.stringify(node.text)}`);
  }
  ts.forEachChild(node, (child) => visit(file, child, out));
};
for (const file of readdirSync(join(promo, "src")).filter((f) => f.endsWith(".tsx") || f === "copy.ts")) {
  const source = ts.createSourceFile(file, read(join(promo, "src", file)), ts.ScriptTarget.Latest, true,
    file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  visit(file, source, problems);
}

const output = read(join(promo, "assets", "scan_output.txt")).split("\n");
for (const [name, lines] of Object.entries({ summary: data.terminal.summary, attack: data.terminal.attack })) {
  const at = output.findIndex((_, i) => lines.every((l, j) => output[i + j] === l));
  if (lines.length === 0 || at < 0) problems.push(`terminal.${name} is not a contiguous run of assets/scan_output.txt`);
}

if (problems.length) {
  for (const p of problems) console.error("PROBLEM:", p);
  process.exit(1);
}
console.log(`ok: ${Object.keys(data.claims).length} claims match eval/claims.json; no hand-typed numbers; terminal text is the real output`);
