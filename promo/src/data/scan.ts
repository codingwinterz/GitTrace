// The real scan the video replays (public/scan_output.txt, the stdout of
// SCAN_COMMAND) and the real call path it draws (public/scan_result.json,
// the same scan as JSON). Lines are only sliced, never edited or reordered.
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

export const useScanOutput = (): string[] | null => {
  const [lines, setLines] = useState<string[] | null>(null);
  const [handle] = useState(() => delayRender("loading scan_output.txt"));
  useEffect(() => {
    fetch(staticFile("scan_output.txt"))
      .then((r) => r.text())
      .then((text) => {
        setLines(text.replace(/\r\n/g, "\n").split("\n"));
        continueRender(handle);
      });
  }, [handle]);
  return lines;
};
