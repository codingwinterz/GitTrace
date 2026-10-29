import React from "react";
import { interpolate, useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { SCAN_COMMAND, sliceSummary, useScanOutput } from "../data/scan";
import { theme } from "../theme";
import { ease, Scene, useEnter } from "../components/ui";

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;
const FONT = 22;
const LINE = 29;
const PAD = 26;

// The real stdout, line for line: the command types out, the output appears
// in order with a blinking cursor, then the view zooms to the three findings
// (the wider header lines fade out, so no line is cut at the edge).
export const Terminal: React.FC = () => {
  const frame = useCurrentFrame();
  const title = useEnter(0);
  const win = useEnter(10, 40);
  const all = useScanOutput();
  if (!all) {
    return null;
  }
  const lines = sliceSummary(all);
  const typed = Math.floor(interpolate(frame, [26, 64], [0, SCAN_COMMAND.length], clamp));
  const shown = Math.floor(interpolate(frame, [70, 140], [0, lines.length], clamp));
  const zoomT = ease(frame, 168, 196);
  const firstFinding = lines.findIndex((l) => l.startsWith("1. "));
  const focusY = PAD + (1 + firstFinding + 4.5) * LINE;
  const cursorOn = Math.floor(frame / 15) % 2 === 0;
  const cursor = <span style={{ opacity: cursorOn ? 1 : 0, background: theme.accent, color: theme.bg }}> </span>;
  const typing = typed < SCAN_COMMAND.length;
  return (
    <Scene>
      <div style={{ position: "absolute", top: 78, left: 60, right: 60, textAlign: "center", whiteSpace: "nowrap",
        fontSize: 46, fontWeight: 800, ...title }}>{copy.terminalTitle}</div>
      <div style={{ position: "absolute", top: 190, left: 60, right: 60, bottom: 70, overflow: "hidden", borderRadius: 20,
        background: theme.panel, border: `2px solid ${theme.line}`, boxShadow: "0 30px 80px rgba(0,0,0,0.45)", ...win }}>
        <div style={{ transform: `translateY(${-190 * zoomT}px) scale(${1 + 0.3 * zoomT})`, transformOrigin: `${PAD}px ${focusY}px`,
          padding: `${PAD}px 30px`, fontFamily: theme.mono, fontSize: FONT, lineHeight: `${LINE}px`, whiteSpace: "pre" }}>
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
