import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { copy } from "../copy";
import { callPath } from "../data/scan";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { Caption, ease, Scene } from "../components/ui";

const STEP = 44;          // frames between nodes
const LAP = 90;           // frames for the pulse to travel the whole path

type Step = { role: string; label: string; tag?: string; sink?: boolean };

// The real path from the scan: route -> handler -> ... -> dangerous sink.
const steps: Step[] = [
  { role: copy.roles.route, label: callPath.endpoint, tag: callPath.authRequired ? undefined : copy.noAuth },
  ...callPath.functions.map((f, i) => ({ role: i === 0 ? copy.roles.handler : copy.roles.calls, label: f })),
  { role: copy.roles.sink, label: `${callPath.sink}  ${callPath.sinkAt}`, sink: true },
];
const last = steps.length - 1;
const appear = (i: number) => 20 + i * STEP;

// Square: one column, top to bottom. Wide: left to right, stepping down,
// the route at the top left and the sink at the bottom right.
type Box = { x: number; y: number; w: number; h: number };
const MONO_EM = 0.6;      // the monospace advance, in em
const textWidth = (s: Step, font: number) =>
  s.label.length * font * MONO_EM + (s.tag ? s.tag.length * 0.66 * 30 + 24 : 0);

const boxes = (wide: boolean, margin: number, width: number): Box[] => {
  if (!wide) {
    const nodeH = 96;
    const row = 34 + nodeH + 64;
    return steps.map((s, i) => {
      const w = textWidth(s, 44) + 68;
      return { x: width / 2 - w / 2, y: 60 + i * row + 34, w, h: nodeH };
    });
  }
  const font = 40;
  const nodeH = 92;
  const widths = steps.map((s) => textWidth(s, font) + 64);
  const span = width - 2 * margin - widths[0] / 2 - widths[last] / 2;
  const top = 150;
  const drop = (800 - top - nodeH) / last;
  return steps.map((_, i) => {
    const cx = margin + widths[0] / 2 + (span * i) / last;
    return { x: cx - widths[i] / 2, y: top + i * drop, w: widths[i], h: nodeH };
  });
};

const Node: React.FC<{ step: Step; i: number; box: Box; active: number; font: number }> = ({ step, i, box, active, font }) => {
  const roleSize = font === 40 ? 30 : 26;
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - appear(i), fps, config: { damping: 14, stiffness: 120 } });
  const sinkOn = step.sink ? ease(frame, appear(i) + 30, appear(i) + 50) : 0;
  const pulse = step.sink ? sinkOn * (0.5 + 0.5 * Math.sin((frame - appear(i)) / 6)) : 0;
  const border = step.sink ? `rgba(255,77,94,${0.4 + 0.6 * sinkOn})` : active > 0.05 ? theme.accent : theme.line;
  return (
    <div style={{ position: "absolute", left: box.x, top: box.y - 38, width: box.w, display: "flex", flexDirection: "column",
      alignItems: "center", opacity: p, transform: `scale(${0.86 + 0.14 * p})` }}>
      <div style={{ height: 38, fontSize: roleSize, letterSpacing: 3, textTransform: "uppercase",
        color: step.sink ? theme.danger : theme.muted }}>{step.role}</div>
      <div style={{ height: box.h, width: box.w, boxSizing: "border-box", display: "flex", alignItems: "center", justifyContent: "center",
        borderRadius: 18, fontFamily: theme.mono, fontSize: font, whiteSpace: "nowrap",
        background: step.sink ? `rgba(255,77,94,${0.1 + 0.2 * pulse})` : theme.panel, border: `3px solid ${border}`,
        boxShadow: step.sink
          ? `0 0 ${24 + 50 * pulse}px rgba(255,77,94,${0.3 + 0.45 * pulse})`
          : `0 0 ${40 * active}px rgba(143,178,255,${0.55 * active})` }}>
        {step.label}
        {step.tag ? <span style={{ marginLeft: 20, fontFamily: theme.sans, fontSize: 30, fontWeight: 800, color: theme.danger }}>{step.tag}</span> : null}
      </div>
    </div>
  );
};

export const CallPath: React.FC = () => {
  const frame = useCurrentFrame();
  const { width } = useVideoConfig();
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const b = boxes(wide, margin, width);
  // The edge into node i, as points. Square: straight down from the node
  // above. Wide: down from the previous node's bottom centre, then right into
  // this node's left side (an elbow, so it never runs backwards).
  const edge = (i: number): { x: number; y: number }[] => {
    const prev = b[i - 1];
    if (!wide) {
      return [{ x: width / 2, y: prev.y + prev.h }, { x: width / 2, y: b[i].y - 34 }];
    }
    const cx = prev.x + prev.w / 2;
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
  const travel = interpolate((frame - travelStart) % LAP, [0, LAP - 1], [0, last], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const activeOf = (i: number) => (traveling ? Math.max(0, 1 - Math.abs(travel - i)) : 0);
  const seg = Math.min(Math.floor(travel), last - 1);
  const dot = along(edge(seg + 1), Math.min(1, travel - seg));
  return (
    <Scene>
      <svg width={width} height={1080} style={{ position: "absolute", inset: 0 }}>
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
      {steps.map((s, i) => <Node key={s.label} step={s} i={i} box={b[i]} active={activeOf(i)} font={wide ? 40 : 44} />)}
      <Caption text={copy.pathCaption} at={appear(last) + 70} />
    </Scene>
  );
};
