// The real scan the video replays and the real call path it draws: GitTrace
// 2.1.0 on tests/fixtures/sample_app. The same scan is captured twice, as
// printed at two terminal widths: COLUMNS=60 for the square video
// (public/scan_output.txt) and COLUMNS=90 for the wide one
// (public/scan_output_90.txt); public/scan_result.json is the same scan as
// JSON. Lines are only sliced, never edited or reordered, with one exception:
// the big block-letter counts at the top of the summary panel become one plain
// line ("N findings · M critical"), with both numbers read from the JSON.
import { useEffect, useState } from "react";
import { continueRender, delayRender, staticFile } from "remotion";
import { copy } from "../copy";
import scanResult from "../../public/scan_result.json";

export const SCAN_COMMAND = "gittrace scan sample_app --no-llm --no-blame --fail-on none";
export const FINDING = "app/utils/shell.py::8::9";
export const ROUTE = "GET /api/users/{name}/files -> app/routers/users.py::list_files";

const finding = scanResult.findings.find((f) => f.id === FINDING);
if (!finding) {
  throw new Error(`public/scan_result.json has no finding ${FINDING}`);
}
const route = finding.reachability.routes.find((r) => r.endpoint === ROUTE);
if (!route) {
  throw new Error(`finding ${FINDING} has no route ${ROUTE}`);
}

// Route -> handler -> ... -> the function holding the sink, then the sink.
export const callPath = {
  endpoint: `${route.method} ${route.path}`,
  authRequired: route.auth_required,
  functions: route.path_nodes.slice(1),
  sink: finding.callee,
  sinkAt: `${finding.location.file}:${finding.location.line}`,
  rule: finding.title,
};

// The output's header panel and the findings list up to the first finding
// that is not critical (contiguous lines, as printed).
export const sliceSummary = (lines: string[]): string[] => {
  const end = lines.findIndex((l) => /^\d+\. /.test(l) && !l.includes("CRITICAL"));
  return plainCounts(lines.slice(0, end < 0 ? lines.length : end));
};

// The panel's block-letter rows (only box edges, spaces and █) replaced by
// one line of plain text, padded to the panel's width.
const BIG = /^│[ █]*█[ █]*│$/;
export const countsLine = `${scanResult.summary.total} ${copy.findings} · ${scanResult.summary.by_severity.critical} ${copy.critical}`;
const plainCounts = (lines: string[]): string[] => {
  const first = lines.findIndex((l) => BIG.test(l));
  if (first < 0) {
    return lines;
  }
  let end = first;
  while (end < lines.length && BIG.test(lines[end])) {
    end++;
  }
  const width = [...lines[first]].length;
  return [...lines.slice(0, first), `│ ${countsLine.padEnd(width - 3)}│`, ...lines.slice(end)];
};

// Where the drawn finding sits in the replay: its "Location:" line.
export const findingLocation = `Location: ${callPath.sinkAt}`;

export const SCAN_OUTPUT = { square: "scan_output.txt", wide: "scan_output_90.txt" } as const;

export const useScanOutput = (file: string): string[] | null => {
  const [lines, setLines] = useState<string[] | null>(null);
  const [handle] = useState(() => delayRender(`loading ${file}`));
  useEffect(() => {
    fetch(staticFile(file))
      .then((r) => r.text())
      .then((text) => {
        setLines(text.replace(/\r\n/g, "\n").split("\n"));
        continueRender(handle);
      });
  }, [handle, file]);
  return lines;
};
