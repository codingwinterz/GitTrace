import React from "react";
import { AbsoluteFill, Easing, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { copy } from "./copy";
import data from "./data.generated.json";
import { theme } from "./theme";

const fadeUp = (frame: number, at: number, len = 14) => ({
  opacity: interpolate(frame, [at, at + len], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }),
  transform: `translateY(${interpolate(frame, [at, at + len], [24, 0], {
    extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.out(Easing.cubic),
  })}px)`,
});

const fadeOut = (frame: number, at: number, len = 10) =>
  interpolate(frame, [at, at + len], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

const Frame: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AbsoluteFill style={{ backgroundColor: theme.bg, color: theme.text, fontFamily: theme.sans }}>
    {children}
  </AbsoluteFill>
);

// Captions sit in the lower-middle band, inside the title-safe area.
const Caption: React.FC<{ text: string; at: number }> = ({ text, at }) => {
  const frame = useCurrentFrame();
  return (
    <div style={{
      position: "absolute", left: theme.side, right: theme.side, top: 820, textAlign: "center",
      fontSize: 44, lineHeight: 1.25, fontWeight: 600, ...fadeUp(frame, at),
    }}>{text}</div>
  );
};

export const Hook: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Frame>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: theme.side, textAlign: "center" }}>
        <div style={{ fontSize: 84, fontWeight: 800, lineHeight: 1.1, ...fadeUp(frame, 6) }}>{copy.hook[0]}</div>
        <div style={{ fontSize: 84, fontWeight: 800, lineHeight: 1.1, marginTop: 40, color: theme.accent, ...fadeUp(frame, 40) }}>
          {copy.hook[1]}
        </div>
      </AbsoluteFill>
    </Frame>
  );
};

// The real `gittrace scan` stdout, line for line: the command types out, the
// output lines appear in order, then the view zooms on the three findings.
export const Terminal: React.FC = () => {
  const frame = useCurrentFrame();
  const { command, summary } = data.terminal;
  const typed = Math.floor(interpolate(frame, [22, 52], [0, command.length], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }));
  const shown = Math.floor(interpolate(frame, [56, 112], [0, summary.length], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }));
  // Then crop to the three findings: zoom from the left edge (the findings
  // lines are short enough to stay whole) and fade the wider header lines out.
  const zoomT = interpolate(frame, [124, 146], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.inOut(Easing.cubic) });
  const zoom = 1 + 0.35 * zoomT;
  const firstFinding = summary.findIndex((l) => l.startsWith("1. "));
  const focusY = 26 + (1 + firstFinding + 4.5) * 29;     // the middle of findings 1-3, in px inside the window
  return (
    <Frame>
      <div style={{ position: "absolute", top: 80, left: 60, right: 60, textAlign: "center", whiteSpace: "nowrap",
        fontSize: 48, fontWeight: 800, ...fadeUp(frame, 0) }}>{copy.terminalTitle}</div>
      <div style={{ position: "absolute", top: 190, left: theme.side - 20, right: theme.side - 20, bottom: 60,
        overflow: "hidden", borderRadius: 18, background: theme.panel, border: `2px solid ${theme.line}`, ...fadeUp(frame, 10) }}>
        <div style={{ transform: `translateY(${-190 * zoomT}px) scale(${zoom})`, transformOrigin: `30px ${focusY}px`, padding: "26px 30px",
          fontFamily: theme.mono, fontSize: 22, lineHeight: "29px", whiteSpace: "pre", color: theme.text }}>
          <div style={{ opacity: 1 - zoomT }}><span style={{ color: theme.accent }}>$ </span>{command.slice(0, typed)}</div>
          {summary.slice(0, shown).map((l, i) => (
            <div key={i} style={{ color: l.includes("NO AUTH") ? theme.accent : theme.text,
              opacity: i < firstFinding ? 1 - zoomT : 1 }}>{l || " "}</div>
          ))}
        </div>
      </div>
    </Frame>
  );
};

const Node: React.FC<{ role: string; label: string; tag?: string; at: number; sink?: boolean }> = ({ role, label, tag, at, sink }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const pop = spring({ frame: frame - at, fps, config: { damping: 14 } });
  const pulse = sink ? 0.5 + 0.5 * Math.sin(Math.max(0, frame - at - 20) / 6) : 0;
  return (
    <div style={{ opacity: pop, transform: `scale(${0.85 + 0.15 * pop})`, display: "flex", flexDirection: "column", alignItems: "center" }}>
      <div style={{ fontSize: 26, color: sink ? theme.accent : theme.muted, letterSpacing: 2, textTransform: "uppercase", marginBottom: 8 }}>{role}</div>
      <div style={{
        fontFamily: theme.mono, fontSize: 40, padding: "18px 30px", borderRadius: 16,
        background: sink ? `rgba(255,77,94,${0.12 + 0.18 * pulse})` : theme.panel,
        border: `3px solid ${sink ? theme.accent : theme.line}`,
        boxShadow: sink ? `0 0 ${20 + 40 * pulse}px rgba(255,77,94,${0.35 + 0.4 * pulse})` : "none",
      }}>
        {label}
        {tag ? <span style={{ marginLeft: 18, fontFamily: theme.sans, fontSize: 28, fontWeight: 800, color: theme.accent }}>{tag}</span> : null}
      </div>
    </div>
  );
};

const Edge: React.FC<{ at: number }> = ({ at }) => {
  const frame = useCurrentFrame();
  const h = interpolate(frame, [at, at + 14], [0, 46], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return <div style={{ height: 46, display: "flex", justifyContent: "center" }}><div style={{ width: 4, height: h, background: theme.muted }} /></div>;
};

// One real route -> handler -> ... -> sink path from the scan (data.path).
export const CallPath: React.FC = () => {
  const p = data.path;
  const steps = [
    { role: copy.roles.route, label: p.endpoint, tag: p.auth_required ? undefined : copy.noAuth },
    ...p.functions.map((f, i) => ({ role: i === 0 ? copy.roles.handler : copy.roles.calls, label: f, tag: undefined })),
  ];
  const gap = 55;
  return (
    <Frame>
      <AbsoluteFill style={{ alignItems: "center", paddingTop: 70 }}>
        {steps.map((s, i) => (
          <React.Fragment key={s.label}>
            {i > 0 ? <Edge at={20 + i * gap - 16} /> : null}
            <Node role={s.role} label={s.label} tag={s.tag} at={20 + i * gap} />
          </React.Fragment>
        ))}
        <Edge at={20 + steps.length * gap - 16} />
        <Node role={copy.roles.sink} label={`${p.sink}  ${p.sink_at}`} at={20 + steps.length * gap} sink />
      </AbsoluteFill>
      <Caption text={copy.pathCaption} at={20 + steps.length * gap + 40} />
    </Frame>
  );
};

export const Why: React.FC = () => {
  const frame = useCurrentFrame();
  const slots = [36, 112, 188];
  const keepAt = 268;
  return (
    <Frame>
      <div style={{ position: "absolute", top: 110, left: theme.side, right: theme.side, textAlign: "center",
        fontSize: 64, fontWeight: 800, lineHeight: 1.15, ...fadeUp(frame, 0) }}>{copy.why}</div>
      {copy.cards.map((c, i) => {
        const end = i < slots.length - 1 ? slots[i + 1] - 6 : keepAt - 6;
        return (
          <div key={c} style={{ position: "absolute", top: 400, left: theme.side, right: theme.side,
            opacity: frame < slots[i] ? 0 : fadeUp(frame, slots[i]).opacity * fadeOut(frame, end),
            transform: fadeUp(frame, slots[i]).transform }}>
            <div style={{ background: theme.panel, border: `2px solid ${theme.line}`, borderLeft: `10px solid ${theme.accent}`,
              borderRadius: 20, padding: "48px 44px", fontSize: 54, fontWeight: 700, lineHeight: 1.2 }}>{c}</div>
          </div>
        );
      })}
      <div style={{ position: "absolute", top: 400, left: theme.side, right: theme.side, textAlign: "center",
        fontSize: 56, fontWeight: 700, lineHeight: 1.25, ...fadeUp(frame, keepAt) }}>{copy.keep}</div>
    </Frame>
  );
};

type Claim = (typeof data.claims)["reachUntouched"];

// A claim as "N marked, M wrong", counted up from zero, with its run label.
const ClaimTile: React.FC<{ claim: Claim; at: number }> = ({ claim, at }) => {
  const frame = useCurrentFrame();
  const t = interpolate(frame, [at, at + 30], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.out(Easing.cubic) });
  const marked = Math.round(claim.marked * t);
  const wrong = Math.round(claim.wrong * t);
  return (
    <div data-claim-id={claim.claim_id} style={{ flex: 1, background: theme.panel, border: `2px solid ${theme.line}`,
      borderRadius: 18, padding: "22px 26px", ...fadeUp(frame, at - 8) }}>
      <div style={{ display: "inline-block", fontFamily: theme.mono, fontSize: 26, color: theme.bg, background: theme.muted,
        borderRadius: 8, padding: "4px 12px" }}>{claim.label}</div>
      <div style={{ marginTop: 12, fontSize: 40, fontWeight: 800, whiteSpace: "nowrap" }}>
        {marked} {copy.marked}, <span style={{ color: claim.wrong ? theme.accent : theme.text }}>{wrong} {copy.wrong}</span>
      </div>
    </div>
  );
};

export const Numbers: React.FC = () => {
  const frame = useCurrentFrame();
  const c = data.claims;
  const limitAt = 196;
  const out = fadeOut(frame, limitAt - 12);
  const row = (title: string, a: Claim, b: Claim, at: number) => (
    <div style={{ marginTop: 28 }}>
      <div style={{ fontSize: 36, fontWeight: 700, color: theme.muted, marginBottom: 12, ...fadeUp(frame, at - 10) }}>{title}</div>
      <div style={{ display: "flex", gap: 24 }}>
        <ClaimTile claim={a} at={at} />
        <ClaimTile claim={b} at={at + 16} />
      </div>
    </div>
  );
  return (
    <Frame>
      <div style={{ position: "absolute", top: 80, left: theme.side, right: theme.side, opacity: out }}>
        <div style={{ fontSize: 66, fontWeight: 800, ...fadeUp(frame, 0) }}>{copy.numbersTitle}</div>
        <div style={{ fontSize: 30, color: theme.muted, marginTop: 10, lineHeight: 1.3, ...fadeUp(frame, 6) }}>{copy.numbersCaption}</div>
        {row(copy.reachable, c.reachUntouched, c.reachLater, 30)}
        {row(copy.withoutAuth, c.unauthUntouched, c.unauthLater, 80)}
        <div style={{ marginTop: 26, fontSize: 32, lineHeight: 1.3, ...fadeUp(frame, 130) }}>{copy.wrongOne}</div>
      </div>
      <div style={{ position: "absolute", top: 330, left: theme.side, right: theme.side, ...fadeUp(frame, limitAt) }}>
        <div style={{ background: theme.panel, border: `2px solid ${theme.line}`, borderLeft: `10px solid ${theme.accent}`,
          borderRadius: 20, padding: "44px 44px" }}>
          <div style={{ fontSize: 40, fontWeight: 800, color: theme.accent, textTransform: "uppercase", letterSpacing: 3 }}>{copy.limitTitle}</div>
          <div style={{ marginTop: 18, fontSize: 50, fontWeight: 700, lineHeight: 1.22 }}>{copy.limit}</div>
        </div>
      </div>
    </Frame>
  );
};

export const Outro: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Frame>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: theme.side, textAlign: "center" }}>
        <div style={{ fontSize: 96, fontWeight: 900, letterSpacing: -1, ...fadeUp(frame, 0) }}>GitTrace</div>
        <div style={{ fontSize: 50, fontWeight: 700, marginTop: 20, lineHeight: 1.2, ...fadeUp(frame, 8) }}>{copy.tagline}</div>
        <div style={{ fontSize: 46, color: theme.accent, marginTop: 50, fontWeight: 700, ...fadeUp(frame, 18) }}>{data.repo_url}</div>
        <div style={{ fontFamily: theme.mono, fontSize: 23, marginTop: 36, padding: "14px 18px", borderRadius: 12,
          background: theme.panel, border: `2px solid ${theme.line}`, whiteSpace: "pre", ...fadeUp(frame, 26) }}>{data.install}</div>
      </AbsoluteFill>
    </Frame>
  );
};
