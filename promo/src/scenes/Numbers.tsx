import React from "react";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { claim, Claim, SHOWN } from "../data/claims";
import { theme } from "../theme";
import { fadeOut, Scene, useEnter } from "../components/ui";

const LIMIT_AT = 300;

// One claim, "N marked, M wrong", counted up from zero, with its run label.
const ClaimCard: React.FC<{ c: Claim; at: number; tag?: string }> = ({ c, at, tag }) => {
  const frame = useCurrentFrame();
  const enter = useEnter(at - 6, 40);
  const t = interpolate(frame, [at, at + 36], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.out(Easing.cubic) });
  return (
    <div data-claim-id={c.claim_id} style={{ flex: 1, background: theme.panel, border: `2px solid ${theme.line}`,
      borderRadius: 20, padding: "22px 26px", ...enter }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <span style={{ fontFamily: theme.mono, fontSize: 26, color: theme.bg, background: theme.accent, borderRadius: 8,
          padding: "4px 12px" }}>{c.label}</span>
        {tag ? <span style={{ fontSize: 26, color: theme.muted }}>{tag}</span> : null}
      </div>
      <div style={{ marginTop: 12, fontSize: 50, fontWeight: 800, lineHeight: 1.15 }}>
        <div>{Math.round(c.marked * t)} {copy.marked},</div>
        <div style={{ color: c.wrong ? theme.danger : theme.text }}>{Math.round(c.wrong * t)} {copy.wrong}</div>
      </div>
    </div>
  );
};

export const Numbers: React.FC = () => {
  const frame = useCurrentFrame();
  const title = useEnter(0);
  const sub = useEnter(8);
  const r1 = useEnter(24);
  const r2 = useEnter(110);
  const note = useEnter(190);
  const limit = useEnter(LIMIT_AT, 50);
  const out = fadeOut(frame, LIMIT_AT - 16);
  return (
    <Scene>
      <div style={{ position: "absolute", top: 62, left: theme.side, right: theme.side, opacity: out }}>
        <div style={{ fontSize: 68, fontWeight: 800, ...title }}>{copy.numbersTitle}</div>
        <div style={{ fontSize: 34, color: theme.muted, marginTop: 4, ...sub }}>{copy.numbersCaption}</div>
        <div style={{ fontSize: 38, fontWeight: 700, color: theme.muted, marginTop: 24, marginBottom: 10, ...r1 }}>{copy.reachable}</div>
        <div style={{ display: "flex", gap: 24 }}>
          <ClaimCard c={claim(SHOWN.reachUntouched)} at={34} />
          <ClaimCard c={claim(SHOWN.reachLater)} at={50} />
        </div>
        <div style={{ fontSize: 38, fontWeight: 700, color: theme.muted, marginTop: 24, marginBottom: 10, ...r2 }}>{copy.withoutAuth}</div>
        <div style={{ display: "flex", gap: 24 }}>
          <ClaimCard c={claim(SHOWN.unauthUntouched)} at={120} tag={copy.before} />
          <ClaimCard c={claim(SHOWN.unauthLater)} at={150} tag={copy.after} />
        </div>
        <div style={{ marginTop: 22, fontSize: 34, lineHeight: 1.3, ...note }}>{copy.wrongOne}</div>
      </div>
      <div style={{ position: "absolute", top: 300, left: theme.side, right: theme.side, ...limit, opacity: frame < LIMIT_AT ? 0 : Number(limit.opacity) }}>
        <div style={{ background: theme.panel, border: `2px solid ${theme.line}`, borderLeft: `10px solid ${theme.danger}`,
          borderRadius: 22, padding: "46px 46px" }}>
          <div style={{ fontSize: 40, fontWeight: 800, color: theme.danger, textTransform: "uppercase", letterSpacing: 3 }}>{copy.limitTitle}</div>
          <div style={{ marginTop: 18, fontSize: 52, fontWeight: 700, lineHeight: 1.22 }}>{copy.limit}</div>
        </div>
      </div>
    </Scene>
  );
};
