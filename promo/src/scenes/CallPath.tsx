import React from "react";
import { Easing, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { copy } from "../copy";
import { callPath } from "../data/scan";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { Caption, ease, Scene } from "../components/ui";

const STEP = 40;          // frames between nodes
const LAP = 90;           // frames for the pulse to travel the whole path

type Step = { role: string; label: string; tag?: string; sink?: boolean };

// The real path from the scan: route -> handler -> ... -> dangerous sink.
const steps: Step[] = [
  { role: copy.roles.route, label: callPath.endpoint, tag: callPath.authRequired ? undefined : copy.noAuth },
  ...callPath.functions.map((f, i) => ({ role: i === 0 ? copy.roles.handler : copy.roles.calls, label: f })),
  { role: copy.roles.sink, label: `${callPath.sink}  ${callPath.sinkAt}`, sink: true },
];
const last = steps.length - 1;
const appear = (i: number) => 4 + i * STEP;   // the route is up as the crossfade ends

// Sizes per layout: node text, box height, the role label above each box.
const SIZES = {
  square: { font: 34, nodeH: 72, role: 26, roleH: 34, tag: 26 },
  wide: { font: 40, nodeH: 92, role: 36, roleH: 46, tag: 36 },
};

// Square: one column, top to bottom. Wide: a staircase across the full width,
// left to right: each box starts further right and one row lower, the route
// at the top left and the sink at the bottom right.
type Box = { x: number; y: number; w: number; h: number };
const MONO_EM = 0.6;      // the monospace advance, in em
const SANS_EM = 0.66;     // a bold capital in the sans face, in em
const textWidth = (s: Step, font: number, tag: number) =>
  s.label.length * font * MONO_EM + (s.tag ? s.tag.length * SANS_EM * tag + 24 : 0);

const boxes = (wide: boolean, margin: number, width: number): Box[] => {
  const z = SIZES[wide ? "wide" : "square"];
  const widths = steps.map((s) => textWidth(s, z.font, z.tag) + 64);
  if (!wide) {
    const row = z.roleH + z.nodeH + 44;
    return steps.map((_, i) => ({ x: width / 2 - widths[i] / 2, y: 64 + z.roleH + i * row, w: widths[i], h: z.nodeH }));
  }
  // The largest step that keeps every box inside the right margin.
  const dx = Math.min(...widths.map((w, i) => (i ? (width - 2 * margin - w) / i : Infinity)));
  const top = margin + z.roleH + 6;
  const drop = 152;
  return steps.map((_, i) => ({ x: margin + i * dx, y: top + i * drop, w: widths[i], h: z.nodeH }));
};

const Node: React.FC<{ step: Step; i: number; box: Box; active: number; wide: boolean }> = ({ step, i, box, active, wide }) => {
  const z = SIZES[wide ? "wide" : "square"];
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - appear(i), fps, config: { damping: 14, stiffness: 120 } });
  const sinkOn = step.sink ? ease(frame, appear(i) + 30, appear(i) + 50) : 0;
  const pulse = step.sink ? sinkOn * (0.5 + 0.5 * Math.sin((frame - appear(i)) / 6)) : 0;
  const border = step.sink ? `rgba(255,77,94,${0.4 + 0.6 * sinkOn})` : active > 0.05 ? theme.accent : theme.line;
  return (
    <div style={{ position: "absolute", left: box.x, top: box.y - z.roleH, width: box.w, display: "flex", flexDirection: "column",
      alignItems: wide ? "flex-start" : "center", opacity: p, transform: `scale(${0.86 + 0.14 * p})`, transformOrigin: wide ? "left center" : "center" }}>
      <div style={{ height: z.roleH, fontSize: z.role, letterSpacing: 3, textTransform: "uppercase", paddingLeft: wide ? 6 : 0,
        color: step.sink ? theme.danger : theme.muted }}>{step.role}</div>
      <div style={{ height: box.h, width: box.w, boxSizing: "border-box", display: "flex", alignItems: "center", justifyContent: "center",
        borderRadius: 18, fontFamily: theme.mono, fontSize: z.font, whiteSpace: "nowrap",
        background: step.sink ? `rgba(255,77,94,${0.1 + 0.2 * pulse})` : theme.panel, border: `3px solid ${border}`,
        boxShadow: step.sink
          ? `0 0 ${24 + 50 * pulse}px rgba(255,77,94,${0.3 + 0.45 * pulse})`
          : `0 0 ${40 * active}px rgba(143,178,255,${0.55 * active})` }}>
        {step.label}
        {step.tag ? <span style={{ marginLeft: 20, fontFamily: theme.sans, fontSize: z.tag, fontWeight: 800, color: theme.danger }}>{step.tag}</span> : null}
      </div>
    </div>
  );
};

export const CallPath: React.FC = () => {
  const frame = useCurrentFrame();
  const { width, height } = useVideoConfig();
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const z = SIZES[wide ? "wide" : "square"];
  const b = boxes(wide, margin, width);
  // The edge into node i, as points. Square: straight down from the node
  // above. Wide: down from a point near the previous box's left end, then
  // right into this box's left side (an elbow that always runs forward).
  const edge = (i: number): { x: number; y: number }[] => {
    const prev = b[i - 1];
    if (!wide) {
      return [{ x: width / 2, y: prev.y + prev.h }, { x: width / 2, y: b[i].y - z.roleH }];
    }
    const cx = prev.x + (b[i].x - prev.x) / 2;
    const cy = b[i].y + b[i].h / 2;
    return [{ x: cx, y: prev.y + prev.h }, { x: cx, y: cy }, { x: b[i].x, y: cy }];
  };
  const along = (pts: { x: number; y: number }[], t: number) => {
    const lens = pts.slice(1).map((q, k) => Math.hypot(q.x - pts[k].x, q.y - pts[k].y));
    let d = t * lens.reduce((x, y) => x + y, 0);
    for (let k = 0; k < lens.length; k++) {
      if (d <= lens[k] || k === lens.length - 1) {
        const r = lens[k] ? Math.min(1, d / lens[k]) : 0;
        return { x: pts[k].x + (pts[k + 1].x - pts[k].x) * r, y: pts[k].y + (pts[k + 1].y - pts[k].y) * r };
      }
      d -= lens[k];
    }
    return pts[pts.length - 1];
  };
  const travelStart = appear(last) + 40;
  const traveling = frame >= travelStart && frame < travelStart + 2 * LAP;
  const travel = interpolate((frame - travelStart) % LAP, [0, LAP - 1], [0, last],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.inOut(Easing.sin) });
  const activeOf = (i: number) => (traveling ? Math.max(0, 1 - Math.abs(travel - i)) : 0);
  const seg = Math.min(Math.floor(travel), last - 1);
  const dot = along(edge(seg + 1), Math.min(1, travel - seg));
  return (
    <Scene>
      <svg width={width} height={height} style={{ position: "absolute", inset: 0 }}>
        {steps.slice(1).map((_, k) => {
          const i = k + 1;
          const drawn = ease(frame, appear(i) - 18, appear(i) - 2);
          const path = edge(i).map((q, k) => `${k ? "L" : "M"} ${q.x} ${q.y}`).join(" ");
          return <path key={i} d={path} fill="none" pathLength={1} strokeDasharray={1} strokeDashoffset={1 - drawn}
            stroke={i === last ? theme.danger : theme.muted} strokeWidth={4} strokeLinecap="round" strokeLinejoin="round" />;
        })}
        {traveling ? (
          <circle cx={dot.x} cy={dot.y} r={12} fill={theme.accent}
            style={{ filter: `drop-shadow(0 0 14px ${theme.accent})` }} />
        ) : null}
      </svg>
      {steps.map((s, i) => <Node key={s.label} step={s} i={i} box={b[i]} active={activeOf(i)} wide={wide} />)}
      <Caption text={copy.pathCaption} at={appear(last) + 70} />
    </Scene>
  );
};
