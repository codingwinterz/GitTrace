import React from "react";
import { interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { copy } from "../copy";
import { callPath } from "../data/scan";
import { theme } from "../theme";
import { Caption, ease, Scene } from "../components/ui";

const NODE_H = 96;
const GAP = 64;          // vertical space for an edge
const ROLE = 34;         // the role label above a node
const TOP = 60;
const STEP = 44;         // frames between nodes

type Step = { role: string; label: string; tag?: string; sink?: boolean };

// The real path from the scan: route -> handler -> ... -> dangerous sink.
const steps: Step[] = [
  { role: copy.roles.route, label: callPath.endpoint, tag: callPath.authRequired ? undefined : copy.noAuth },
  ...callPath.functions.map((f, i) => ({ role: i === 0 ? copy.roles.handler : copy.roles.calls, label: f })),
  { role: copy.roles.sink, label: `${callPath.sink}  ${callPath.sinkAt}`, sink: true },
];
const rowH = ROLE + NODE_H + GAP;
const nodeTop = (i: number) => TOP + i * rowH + ROLE;
const appear = (i: number) => 20 + i * STEP;

const Node: React.FC<{ step: Step; i: number; active: number }> = ({ step, i, active }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - appear(i), fps, config: { damping: 14, stiffness: 120 } });
  const sinkOn = step.sink ? ease(frame, appear(i) + 30, appear(i) + 50) : 0;
  const pulse = step.sink ? sinkOn * (0.5 + 0.5 * Math.sin((frame - appear(i)) / 6)) : 0;
  const glow = active;
  const color = step.sink ? `rgba(255,77,94,${0.4 + 0.6 * sinkOn})` : theme.line;
  return (
    <div style={{ position: "absolute", top: nodeTop(i) - ROLE, left: 0, right: 0, display: "flex", flexDirection: "column",
      alignItems: "center", opacity: p, transform: `scale(${0.86 + 0.14 * p})` }}>
      <div style={{ height: ROLE, fontSize: 26, letterSpacing: 3, textTransform: "uppercase",
        color: step.sink ? theme.danger : theme.muted }}>{step.role}</div>
      <div style={{ height: NODE_H, display: "flex", alignItems: "center", padding: "0 34px", borderRadius: 18,
        fontFamily: theme.mono, fontSize: 44, background: step.sink ? `rgba(255,77,94,${0.1 + 0.2 * pulse})` : theme.panel,
        border: `3px solid ${step.sink ? color : glow > 0.05 ? theme.accent : theme.line}`,
        boxShadow: step.sink
          ? `0 0 ${24 + 50 * pulse}px rgba(255,77,94,${0.3 + 0.45 * pulse})`
          : `0 0 ${40 * glow}px rgba(143,178,255,${0.55 * glow})` }}>
        {step.label}
        {step.tag ? <span style={{ marginLeft: 20, fontFamily: theme.sans, fontSize: 30, fontWeight: 800, color: theme.danger }}>{step.tag}</span> : null}
      </div>
    </div>
  );
};

export const CallPath: React.FC = () => {
  const frame = useCurrentFrame();
  const last = steps.length - 1;
  // After the last node lands, a light pulse travels the path, twice.
  const travelStart = appear(last) + 40;
  const lap = 90;
  const traveling = frame >= travelStart && frame < travelStart + 2 * lap;
  const travel = interpolate((frame - travelStart) % lap, [0, lap - 1], [0, last], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const activeOf = (i: number) => (traveling ? Math.max(0, 1 - Math.abs(travel - i)) : 0);
  return (
    <Scene>
      <svg width={1080} height={1080} style={{ position: "absolute", inset: 0 }}>
        {steps.slice(1).map((_, k) => {
          const i = k + 1;
          const y1 = nodeTop(i - 1) + NODE_H;
          const y2 = nodeTop(i) - ROLE;
          const drawn = ease(frame, appear(i) - 18, appear(i) - 2);
          return <line key={i} x1={540} x2={540} y1={y1} y2={y1 + (y2 - y1) * drawn} stroke={i === last ? theme.danger : theme.muted}
            strokeWidth={4} strokeLinecap="round" />;
        })}
        {traveling ? (() => {
          const seg = Math.min(Math.floor(travel), last - 1);
          const f = Math.min(1, travel - seg);
          const y = nodeTop(seg) + NODE_H / 2 + (nodeTop(seg + 1) + NODE_H / 2 - nodeTop(seg) - NODE_H / 2) * f;
          return <circle cx={540} cy={y} r={12} fill={theme.accent} style={{ filter: `drop-shadow(0 0 14px ${theme.accent})` }} />;
        })() : null}
      </svg>
      {steps.map((s, i) => <Node key={s.label} step={s} i={i} active={activeOf(i)} />)}
      <Caption text={copy.pathCaption} at={appear(last) + 70} />
    </Scene>
  );
};
