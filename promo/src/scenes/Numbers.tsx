import React from "react";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { claim, Claim, SHOWN } from "../data/claims";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { fadeOut, Scene, useEnter } from "../components/ui";

const LIMIT_AT = 300;

const useCount = (at: number) => {
  const frame = useCurrentFrame();
  return interpolate(frame, [at, at + 36], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.out(Easing.cubic) });
};

const RunTag: React.FC<{ label: string }> = ({ label }) => (
  <span style={{ fontFamily: theme.mono, fontSize: useLayout() === "wide" ? 30 : 26, color: theme.bg, background: theme.accent, borderRadius: 8, padding: "4px 12px" }}>{label}</span>
);

// One claim, "N marked, M wrong", counted up from zero, under its run label.
const Count: React.FC<{ c: Claim; t: number; size: number; split: boolean }> = ({ c, t, size, split }) => (
  <div data-claim-id={c.claim_id} style={{ fontSize: size, fontWeight: 800, lineHeight: 1.15 }}>
    <span style={{ display: split ? "block" : "inline" }}>{Math.round(c.marked * t)} {copy.marked},{split ? null : " "}</span>
    <span style={{ display: split ? "block" : "inline", color: c.wrong ? theme.danger : theme.text }}>{Math.round(c.wrong * t)} {copy.wrong}</span>
  </div>
);

const Card: React.FC<{ at: number; children: React.ReactNode; flex?: number }> = ({ at, children, flex = 1 }) => {
  const enter = useEnter(at - 6, 40);
  return (
    <div style={{ flex, background: theme.panel, border: `2px solid ${theme.line}`, borderRadius: 20, padding: "22px 26px", ...enter }}>
      {children}
    </div>
  );
};

const RunClaim: React.FC<{ c: Claim; at: number; tag?: string; size: number; split: boolean }> = ({ c, at, tag, size, split }) => {
  const t = useCount(at);
  return (
    <div>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <RunTag label={c.label} />
        {tag ? <span style={{ fontSize: useLayout() === "wide" ? 30 : 26, color: theme.muted }}>{tag}</span> : null}
      </div>
      <div style={{ marginTop: 12 }}><Count c={c} t={t} size={size} split={split} /></div>
    </div>
  );
};

const LimitCard: React.FC<{ font: number }> = ({ font }) => (
  <div style={{ background: theme.panel, border: `2px solid ${theme.line}`, borderLeft: `10px solid ${theme.danger}`,
    borderRadius: 22, padding: "36px 44px" }}>
    <div style={{ fontSize: 40, fontWeight: 800, color: theme.danger, textTransform: "uppercase", letterSpacing: 3 }}>{copy.limitTitle}</div>
    <div style={{ marginTop: 14, fontSize: font, fontWeight: 700, lineHeight: 1.22 }}>{copy.limit}</div>
  </div>
);

export const Numbers: React.FC = () => {
  const frame = useCurrentFrame();
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const title = useEnter(0);
  const sub = useEnter(8);
  const r1 = useEnter(24);
  const r2 = useEnter(110);
  const note = useEnter(190);
  const limit = useEnter(LIMIT_AT, 50);
  const shown = (at: number, e: { opacity: number; transform: string }) => ({ ...e, opacity: frame < at ? 0 : Number(e.opacity) });

  // Wide: everything on one screen. The reachable card (both runs) and the two
  // without-auth run cards side by side, the note, then the known limit below.
  if (wide) {
    return (
      <Scene>
        <div style={{ position: "absolute", top: margin - 10, left: margin, right: margin }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 28 }}>
            <div style={{ fontSize: 64, fontWeight: 800, ...title }}>{copy.numbersTitle}</div>
            <div style={{ fontSize: 36, color: theme.muted, ...sub }}>{copy.numbersCaption}</div>
          </div>
          <div style={{ display: "flex", gap: 28, marginTop: 30 }}>
            <Card at={30} flex={1.25}>
              <div style={{ fontSize: 40, fontWeight: 700, color: theme.muted, marginBottom: 14, ...r1 }}>{copy.reachable}</div>
              <RunClaim c={claim(SHOWN.reachUntouched)} at={34} size={44} split={false} />
              <div style={{ height: 18 }} />
              <RunClaim c={claim(SHOWN.reachLater)} at={50} size={44} split={false} />
            </Card>
            <Card at={110}>
              <div style={{ fontSize: 40, fontWeight: 700, color: theme.muted, marginBottom: 14, ...r2 }}>{copy.withoutAuth}</div>
              <RunClaim c={claim(SHOWN.unauthUntouched)} at={120} tag={copy.before} size={50} split />
            </Card>
            <Card at={140}>
              <div style={{ fontSize: 40, fontWeight: 700, color: theme.muted, marginBottom: 14, ...r2 }}>{copy.withoutAuth}</div>
              <RunClaim c={claim(SHOWN.unauthLater)} at={150} tag={copy.after} size={50} split />
            </Card>
          </div>
          <div style={{ marginTop: 22, fontSize: 40, lineHeight: 1.3, ...note }}>{copy.wrongOne}</div>
          <div style={{ marginTop: 28, ...shown(LIMIT_AT, limit) }}><LimitCard font={44} /></div>
        </div>
      </Scene>
    );
  }

  const out = fadeOut(frame, LIMIT_AT - 16);
  return (
    <Scene>
      <div style={{ position: "absolute", top: 62, left: theme.side, right: theme.side, opacity: out }}>
        <div style={{ fontSize: 68, fontWeight: 800, ...title }}>{copy.numbersTitle}</div>
        <div style={{ fontSize: 34, color: theme.muted, marginTop: 4, ...sub }}>{copy.numbersCaption}</div>
        <div style={{ fontSize: 38, fontWeight: 700, color: theme.muted, marginTop: 24, marginBottom: 10, ...r1 }}>{copy.reachable}</div>
        <div style={{ display: "flex", gap: 24 }}>
          <Card at={34}><RunClaim c={claim(SHOWN.reachUntouched)} at={34} size={50} split /></Card>
          <Card at={50}><RunClaim c={claim(SHOWN.reachLater)} at={50} size={50} split /></Card>
        </div>
        <div style={{ fontSize: 38, fontWeight: 700, color: theme.muted, marginTop: 24, marginBottom: 10, ...r2 }}>{copy.withoutAuth}</div>
        <div style={{ display: "flex", gap: 24 }}>
          <Card at={120}><RunClaim c={claim(SHOWN.unauthUntouched)} at={120} tag={copy.before} size={50} split /></Card>
          <Card at={150}><RunClaim c={claim(SHOWN.unauthLater)} at={150} tag={copy.after} size={50} split /></Card>
        </div>
        <div style={{ marginTop: 22, fontSize: 34, lineHeight: 1.3, ...note }}>{copy.wrongOne}</div>
      </div>
      <div style={{ position: "absolute", top: 300, left: theme.side, right: theme.side, ...shown(LIMIT_AT, limit) }}>
        <LimitCard font={52} />
      </div>
    </Scene>
  );
};
