// The real scan the video replays and the real call path it draws. The same
// scan is captured twice, as printed at two terminal widths: COLUMNS=60 for
// the square video (public/scan_output.txt) and COLUMNS=100 for the wide one
// (public/scan_output_100.txt); public/scan_result.json is the same scan as
// JSON. Lines are only sliced, never edited or reordered.
import { useEffect, useState } from "react";
import { continueRender, delayRender, staticFile } from "remotion";
import scanResult from "../../public/scan_result.json";

export const SCAN_COMMAND = "gittrace scan bad --no-llm --no-blame --fail-on none";
const FINDING = "libuser.py::12::12";
const ROUTE = "GET /user/login -> mod_user.py::do_login";

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

// The output's header panel and findings list up to the first finding not
// shown (contiguous lines, as printed).
export const sliceSummary = (lines: string[]): string[] => {
  const end = lines.findIndex((l) => l.startsWith("4. "));
  return lines.slice(0, end < 0 ? lines.length : end);
};

export const SCAN_OUTPUT = { square: "scan_output.txt", wide: "scan_output_100.txt" } as const;

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
