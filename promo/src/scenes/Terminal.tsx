import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { SCAN_COMMAND, SCAN_OUTPUT, sliceSummary, useScanOutput } from "../data/scan";
import { useLayout } from "../layout";
import { theme } from "../theme";
import { ease, Scene, useEnter } from "../components/ui";

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Square: the 60-column capture at 22 px, then a zoom on the findings (the
// wider header lines fade out, so no line is cut at the edge).
// Wide: the 100-column capture at 27 px, whole, no crop or zoom.
const SIZES = {
  square: { font: 22, line: 29, pad: 26, title: 46, top: 190, side: 60, bottom: 70 },
  wide: { font: 27, line: 32, pad: 18, title: 54, top: 176, side: 96, bottom: 96 },
};

// The real stdout, line for line: the command types out and the output
// appears in order with a blinking cursor.
export const Terminal: React.FC = () => {
  const frame = useCurrentFrame();
  const layout = useLayout();
  const wide = layout === "wide";
  const s = SIZES[layout];
  const title = useEnter(0);
  const win = useEnter(10, 40);
  const all = useScanOutput(SCAN_OUTPUT[layout]);
  if (!all) {
    return null;
  }
  const lines = sliceSummary(all);
  const typed = Math.floor(interpolate(frame, [26, 64], [0, SCAN_COMMAND.length], clamp));
  const shown = Math.floor(interpolate(frame, [70, 140], [0, lines.length], clamp));
  const zoomT = wide ? 0 : ease(frame, 168, 196);
  const firstFinding = lines.findIndex((l) => l.startsWith("1. "));
  const focusY = s.pad + (1 + firstFinding + 4.5) * s.line;
  const cursorOn = Math.floor(frame / 15) % 2 === 0;
  const cursor = <span style={{ opacity: cursorOn ? 1 : 0, background: theme.accent, color: theme.bg }}> </span>;
  const typing = typed < SCAN_COMMAND.length;
  return (
    <Scene>
      <div style={{ position: "absolute", top: wide ? 86 : 78, left: s.side, right: s.side, textAlign: "center", whiteSpace: "nowrap",
        fontSize: s.title, fontWeight: 800, ...title }}>{copy.terminalTitle}</div>
      <div style={{ position: "absolute", top: s.top, left: s.side, right: s.side, bottom: s.bottom, overflow: "hidden", borderRadius: 20,
        background: theme.panel, border: `2px solid ${theme.line}`, boxShadow: "0 30px 80px rgba(0,0,0,0.45)", ...win }}>
        <div style={{ transform: `translateY(${-190 * zoomT}px) scale(${1 + 0.3 * zoomT})`, transformOrigin: `${s.pad}px ${focusY}px`,
          padding: `${s.pad}px 30px`, fontFamily: theme.mono, fontSize: s.font, lineHeight: `${s.line}px`, whiteSpace: "pre" }}>
          <div style={{ opacity: 1 - zoomT }}>
            <span style={{ color: theme.accent }}>$ </span>{SCAN_COMMAND.slice(0, typed)}{typing ? cursor : null}
          </div>
          {lines.slice(0, shown).map((l, i) => (
            <div key={i} style={{ color: l.includes("NO AUTH") ? theme.danger : theme.text, opacity: i < firstFinding ? 1 - zoomT : 1 }}>
              {l || " "}
            </div>
          ))}
          {!typing ? <div>{cursor}</div> : null}
        </div>
      </div>
    </Scene>
  );
};
