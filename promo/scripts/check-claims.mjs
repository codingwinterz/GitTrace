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
//      (both captures: 60 columns for the square video, 90 for the wide one);
//      the "N findings · M critical" line that replaces the block letters
//      agrees with the counts the capture itself prints
//   5. both compositions, GitTrace (1080x1080) and GitTrace16x9 (1920x1080),
//      render the same shared GitTrace component, so 1-4 cover both; the
//      bundle is built and both are listed at 30 fps, about 70 s
//   6. no count-up: a claim's marked/wrong reaches the screen unchanged
//   7. the outro's install command is the README's, tagged v<gittrace.__version__>
//   8. timing: the known-limit card is fully visible for at least 4 s, with no
//      crossfade on either side of its scene
//
//   node scripts/check-claims.mjs

import { execFileSync, execSync } from "node:child_process";
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

// 4. The real scan: the drawn route exists, the replay files are the captured
// stdout, and the counts line agrees with what the capture prints.
const constant = (path, name) => {
  let value;
  walk(parse(path), (n) => {
    if (ts.isVariableDeclaration(n) && n.name.getText() === name && n.initializer && ts.isStringLiteral(n.initializer)) value = n.initializer.text;
  });
  return value;
};
const scanTs = join(promo, "src", "data", "scan.ts");
const [FINDING, ROUTE] = [constant(scanTs, "FINDING"), constant(scanTs, "ROUTE")];
const scan = JSON.parse(read(join(promo, "public", "scan_result.json")));
const finding = scan.findings.find((f) => f.id === FINDING);
if (!finding?.reachability.routes.some((r) => r.endpoint === ROUTE)) {
  problems.push(`public/scan_result.json: the drawn route ${ROUTE} (finding ${FINDING}) is not in the scan`);
}
const sev = scan.summary.by_severity;
if (scan.summary.total !== scan.findings.length || sev.critical !== scan.findings.filter((f) => f.severity === "critical").length) {
  problems.push("public/scan_result.json: summary counts do not match its findings");
}
const routeLine = `Reached from: ${ROUTE.split(" -> ")[0]}`;
const sevLine = `${sev.critical} critical   ${sev.high} high   ${sev.medium} medium   ${sev.low} low   ${sev.info} info`;
for (const file of ["scan_output.txt", "scan_output_90.txt"]) {
  const output = read(join(promo, "public", file));
  if (!output.includes(`gittrace scan · ${scan.project}`) || !output.includes(routeLine)) {
    problems.push(`public/${file} is not the captured \`gittrace scan ${scan.project}\` output`);
  }
  if (!output.includes(sevLine)) problems.push(`public/${file}: the panel does not print ${JSON.stringify(sevLine)} (scan_result.json)`);
  if (!/^│[ █]*█[ █]*│$/m.test(output)) problems.push(`public/${file}: no block-letter rows to replace`);
}

// 5. Both compositions, read from src/Root.tsx.
const compositions = [];
walk(parse(join(promo, "src", "Root.tsx")), (n) => {
  if (ts.isJsxSelfClosingElement(n) && n.tagName.getText() === "Composition") {
    const value = (name) => {
      const v = n.attributes.properties.find((a) => a.name?.getText() === name)?.initializer;
      return v && ts.isStringLiteral(v) ? v.text : v?.expression?.getText();
    };
    compositions.push({ id: value("id"), component: value("component"), width: value("width"), height: value("height") });
  }
});
const want = { GitTrace: ["SIZE", "SIZE"], GitTrace16x9: ["1920", "1080"] };
for (const [id, [w, h]] of Object.entries(want)) {
  const c = compositions.find((x) => x.id === id);
  if (!c) problems.push(`src/Root.tsx: no composition ${id}`);
  else if (c.component !== "GitTrace" || c.width !== w || c.height !== h) {
    problems.push(`src/Root.tsx: ${id} must render the shared GitTrace at ${w}x${h} (has ${c.component} at ${c.width}x${c.height})`);
  }
}

const bundled = {};
try {
  // A fixed command line (no arguments passed in); Windows needs a shell for npx.
  const listed = execSync("npx remotion compositions", { cwd: promo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  for (const m of listed.matchAll(/^(\S+)\s+(\d+)\s+(\d+)x(\d+)\s+(\d+) \(/gm)) {
    bundled[m[1]] = { fps: +m[2], width: +m[3], height: +m[4], frames: +m[5] };
  }
} catch (e) {
  problems.push(`remotion compositions failed: ${String(e.stderr || e.message).split("\n").find((l) => /error/i.test(l)) || e.message}`);
}
const size = { GitTrace: [1080, 1080], GitTrace16x9: [1920, 1080] };
for (const [id, [w, h]] of Object.entries(size)) {
  const b = bundled[id];
  if (!b) {
    problems.push(`bundle: no composition ${id}`);
    continue;
  }
  const seconds = b.frames / b.fps;
  if (b.width !== w || b.height !== h || b.fps !== 30 || seconds < 68 || seconds > 72) {
    problems.push(`bundle: ${id} is ${b.width}x${b.height} at ${b.fps} fps, ${seconds.toFixed(2)} s (want ${w}x${h}, 30 fps, about 70 s)`);
  }
}

// 6. No count-up: wherever a scene shows a claim's marked/wrong, it shows it as is.
for (const path of files.filter((f) => /[\\/]scenes[\\/]/.test(f))) {
  const rel = path.slice(promo.length + 1).replace(/\\/g, "/");
  walk(parse(path), (n) => {
    if (ts.isJsxExpression(n) && n.expression && /\.(marked|wrong)\b/.test(n.expression.getText())) {
      // e.g. the old count-up, {Math.round(c.marked * t)}
      const text = n.expression.getText();
      if (/Math\.|interpolate|spring/.test(text) || /\.(marked|wrong)\s*[-+*/%]|[-+*/%]\s*\w+\.(marked|wrong)\b/.test(text)) {
        problems.push(`${rel}: a claim value is changed before it is shown: {${text}}`);
      }
    }
  });
}

// 7. The install command: the README line install.ts reads, tagged with the package version.
const version = /__version__ = "([^"]+)"/.exec(read(join(repo, "gittrace", "__init__.py")))?.[1];
const installLine = read(join(repo, "README.md")).split("\n").find((l) => /^pipx install "?git\+https:\/\/\S+@v\d+\.\d+\.\d+"?(\s|$)/.test(l));
if (!installLine) problems.push("README.md: no `pipx install \"git+...@v<version>\"` line for the outro");
else if (!new RegExp(`@v${version.replace(/\./g, "\\.")}"?(\\s|$)`).test(installLine)) {
  problems.push(`README.md: the install line is not tagged v${version}: ${installLine.split("#")[0].trim()}`);
}

// 8. Timing, from src/timing.json and the storyboard in src/Root.tsx.
const timing = JSON.parse(read(join(promo, "src", "timing.json")));
const limitFrames = Math.round(timing.windowsSeconds.limit * timing.fps);
const fullyVisible = limitFrames - timing.limit.inEnd - timing.limit.outLength;
if (fullyVisible < 4 * timing.fps) problems.push(`the known limit is fully visible for ${(fullyVisible / timing.fps).toFixed(2)} s (< 4 s)`);
const storyboard = [];
walk(parse(join(promo, "src", "Root.tsx")), (n) => {
  if (ts.isJsxElement(n) && n.openingElement.tagName.getText() === "TransitionSeries") {
    for (const c of n.children) {
      if (ts.isJsxExpression(c) && c.expression) storyboard.push("cut");
      else if (ts.isJsxElement(c)) storyboard.push(c.openingElement.attributes.properties.find((a) => a.name?.getText() === "name")?.initializer?.text);
    }
  }
});
const limitAt = storyboard.indexOf("Limit");
if (limitAt < 0) problems.push("src/Root.tsx: no Limit scene");
else if (storyboard[limitAt - 1] === "cut" || storyboard[limitAt + 1] === "cut") problems.push("src/Root.tsx: a crossfade touches the known-limit scene");
const cuts = storyboard.filter((x) => x === "cut").length;
if (cuts !== timing.crossfadeAfter.length) problems.push(`src/Root.tsx has ${cuts} crossfades, src/timing.json counts ${timing.crossfadeAfter.length}`);

if (problems.length) {
  for (const p of problems) console.error("PROBLEM:", p);
  process.exit(1);
}
const listed = Object.entries(bundled).map(([id, b]) => `${id} ${b.width}x${b.height} ${(b.frames / b.fps).toFixed(2)} s`).join(", ");
console.log(`ok: ${listed}; ${shown.length} shown claims (${shown.join(", ")}) are records in eval/claims.json and match their results; ` +
  `no hand-typed or counted-up numbers; the scan data is real; install tag v${version}; known limit fully visible ${(fullyVisible / timing.fps).toFixed(2)} s`);
