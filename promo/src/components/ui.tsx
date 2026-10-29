import React from "react";
import { AbsoluteFill, Easing, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { theme } from "../theme";

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

// An eased entrance: fade and rise, driven by a spring.
export const useEnter = (at: number, distance = 28) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - at, fps, config: { damping: 200, stiffness: 120 } });
  return { opacity: p, transform: `translateY(${(1 - p) * distance}px)` };
};

export const fadeOut = (frame: number, at: number, len = 12) => interpolate(frame, [at, at + len], [1, 0], clamp);

// A faint grid drifting slowly behind every scene.
export const Background: React.FC = () => {
  const frame = useCurrentFrame();
  const step = 72;
  const drift = (frame * 0.35) % step;
  const lines = Array.from({ length: Math.ceil(1080 / step) + 2 }, (_, i) => i * step - drift);
  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg }}>
      <svg width={1080} height={1080} style={{ position: "absolute", inset: 0, opacity: 0.35 }}>
        {lines.map((p) => (
          <React.Fragment key={p}>
            <line x1={p} y1={0} x2={p} y2={1080} stroke={theme.line} strokeWidth={1} />
            <line x1={0} y1={p} x2={1080} y2={p} stroke={theme.line} strokeWidth={1} />
          </React.Fragment>
        ))}
      </svg>
      <AbsoluteFill style={{ background: `radial-gradient(circle at 50% 45%, transparent 0%, ${theme.bg} 75%)` }} />
    </AbsoluteFill>
  );
};

export const Scene: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AbsoluteFill style={{ color: theme.text, fontFamily: theme.sans }}>
    <Background />
    {children}
  </AbsoluteFill>
);

// Captions sit in the lower-middle band.
export const Caption: React.FC<{ text: string; at: number }> = ({ text, at }) => {
  const enter = useEnter(at);
  return (
    <div style={{ position: "absolute", left: theme.side, right: theme.side, top: 830, textAlign: "center",
      fontSize: 48, fontWeight: 700, lineHeight: 1.22, ...enter }}>{text}</div>
  );
};

// Words appear one at a time, each with its own spring.
export const WordReveal: React.FC<{ text: string; at: number; every: number; style?: React.CSSProperties; color?: (i: number) => string }> = ({ text, at, every, style, color }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return (
    <div style={style}>
      {text.split(" ").map((w, i) => {
        const p = spring({ frame: frame - at - i * every, fps, config: { damping: 200, stiffness: 160 } });
        return (
          <span key={i} style={{ display: "inline-block", marginRight: "0.28em", opacity: p,
            transform: `translateY(${(1 - p) * 22}px)`, filter: `blur(${(1 - p) * 6}px)`, color: color?.(i) }}>{w}</span>
        );
      })}
    </div>
  );
};

export const ease = (frame: number, from: number, to: number, a = 0, b = 1) =>
  interpolate(frame, [from, to], [a, b], { ...clamp, easing: Easing.inOut(Easing.cubic) });
