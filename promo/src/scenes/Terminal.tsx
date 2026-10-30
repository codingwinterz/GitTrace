import React from "react";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { findingLocation, SCAN_COMMAND, SCAN_OUTPUT, sliceSummary, useScanOutput } from "../data/scan";
import { useLayout } from "../layout";
import { theme } from "../theme";
import { ease, Scene, useEnter } from "../components/ui";

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// Square: the 60-column capture at 22 px. Wide: the 90-column capture at
// 30 px across the full width (90 x 0.6 x 30 = 1620 px of text).
const SIZES = {
  square: { font: 22, line: 29, pad: 22, title: 46, titleTop: 78, top: 170, side: 60, bottom: 60, padX: 26 },
  wide: { font: 30, line: 36, pad: 18, title: 54, titleTop: 70, top: 160, side: 96, bottom: 96, padX: 30 },
};

const TYPE = [26, 64];      // the command types out
const PANEL = [72, 100];    // then the summary panel prints, and holds
const PRINT = [132, 215];   // then the findings print, line by line
const MARK = 225;           // then the finding the next scene draws is marked

// The real stdout, line for line: the command types out, the output appears in
// order with a blinking cursor, and the window scrolls like a terminal once it
// is full.
export const Terminal: React.FC = () => {
  const frame = useCurrentFrame();
  const layout = useLayout();
  const s = SIZES[layout];
  const title = useEnter(0);
  const win = useEnter(10, 40);
  const all = useScanOutput(SCAN_OUTPUT[layout]);
  if (!all) {
    return null;
  }
  const lines = sliceSummary(all);
  const typed = Math.floor(interpolate(frame, TYPE, [0, SCAN_COMMAND.length], { ...clamp, easing: Easing.inOut(Easing.sin) }));
  const panelEnd = lines.findIndex((l) => /^\d+\. /.test(l));
  const printed = frame < PRINT[0]
    ? interpolate(frame, PANEL, [0, panelEnd], { ...clamp, easing: Easing.inOut(Easing.sin) })
    : interpolate(frame, PRINT, [panelEnd, lines.length], { ...clamp, easing: Easing.inOut(Easing.sin) });
  const shown = Math.floor(printed);
  const cursorOn = Math.floor(frame / 15) % 2 === 0;
  const cursor = <span style={{ opacity: cursorOn ? 1 : 0, background: theme.accent, color: theme.bg }}> </span>;
  const typing = typed < SCAN_COMMAND.length;
  // Lines that fit in the window; the command line and the cursor line count too.
  const visible = Math.floor((1080 - s.top - s.bottom - 2 * s.pad) / s.line);
  const scroll = Math.max(0, printed + 2 - visible) * s.line;
  const at = lines.findIndex((l) => l.trim() === findingLocation);
  const mark = at > 0 ? ease(frame, MARK, MARK + 20) : 0;
  return (
    <Scene>
      <div style={{ position: "absolute", top: s.titleTop, left: s.side, right: s.side, textAlign: "center", whiteSpace: "nowrap",
        fontSize: s.title, fontWeight: 800, ...title }}>{copy.terminalTitle}</div>
      <div style={{ position: "absolute", top: s.top, left: s.side, right: s.side, bottom: s.bottom, overflow: "hidden", borderRadius: 20,
        background: theme.panel, border: `2px solid ${theme.line}`, boxShadow: "0 30px 80px rgba(0,0,0,0.45)", ...win }}>
        {/* Lines scrolling out of the top fade instead of being cut. */}
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: s.line + s.pad, zIndex: 1,
          background: `linear-gradient(${theme.panel} 35%, transparent)`, opacity: scroll > 0 ? 1 : 0 }} />
        <div style={{ position: "relative", transform: `translateY(${-scroll}px)`, padding: `${s.pad}px ${s.padX}px`,
          fontFamily: theme.mono, fontSize: s.font, lineHeight: `${s.line}px`, whiteSpace: "pre" }}>
          {at > 0 ? (
            <div style={{ position: "absolute", left: 8, right: 8, top: s.pad + at * s.line - 4, height: 3 * s.line + 8,
              borderRadius: 10, background: "rgba(143,178,255,0.16)", border: `2px solid ${theme.accent}`, opacity: mark }} />
          ) : null}
          <div style={{ position: "relative" }}>
            <span style={{ color: theme.accent }}>$ </span>{SCAN_COMMAND.slice(0, typed)}{typing ? cursor : null}
          </div>
          {lines.slice(0, shown).map((l, i) => (
            <div key={i} style={{ position: "relative", color: l.includes("NO AUTH") ? theme.danger : theme.text }}>
              {l || " "}
            </div>
          ))}
          {!typing ? <div style={{ position: "relative" }}>{cursor}</div> : null}
        </div>
      </div>
    </Scene>
  );
};
