import React from "react";
import { AbsoluteFill, useCurrentFrame, useVideoConfig } from "remotion";
import { copy } from "../copy";
import { claim, Claim, SHOWN } from "../data/claims";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { fadeOut, Scene, useEnter } from "../components/ui";

const OUT = 14;           // frames: the scene fades its own content out (no crossfade into the known limit)

const RunTag: React.FC<{ label: string; size: number }> = ({ label, size }) => (
  <span style={{ fontFamily: theme.mono, fontSize: size, color: theme.bg, background: theme.accent, borderRadius: 8, padding: "4px 14px" }}>{label}</span>
);

// One claim, "N marked, M wrong", under its run label. The final numbers fade
// in as they are (no counting up), so every frame shows the record's values.
const RunClaim: React.FC<{ c: Claim; at: number; tag?: string; size: number; tagSize: number; split: boolean }> = ({ c, at, tag, size, tagSize, split }) => {
  const frame = useCurrentFrame();
  const enter = useEnter(at, 24);
  return (
    <div data-claim-id={c.claim_id} style={{ ...enter, opacity: frame < at ? 0 : Number(enter.opacity) }}>
      <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
        <RunTag label={c.label} size={tagSize} />
        {tag ? <span style={{ fontSize: tagSize, color: theme.muted }}>{tag}</span> : null}
      </div>
      <div style={{ marginTop: 12, fontSize: size, fontWeight: 800, lineHeight: 1.15 }}>
        <span style={{ display: split ? "block" : "inline" }}>{c.marked} {copy.marked},{split ? null : " "}</span>
        <span style={{ display: split ? "block" : "inline", color: c.wrong ? theme.danger : theme.text }}>{c.wrong} {copy.wrong}</span>
      </div>
    </div>
  );
};

const Card: React.FC<{ at: number; title: string; titleSize: number; pad: string; children: React.ReactNode }> = ({ at, title, titleSize, pad, children }) => {
  const frame = useCurrentFrame();
  const enter = useEnter(at, 40);
  return (
    <div style={{ flex: 1, background: theme.panel, border: `2px solid ${theme.line}`, borderRadius: 22, padding: pad,
      ...enter, opacity: frame < at ? 0 : Number(enter.opacity) }}>
      <div style={{ fontSize: titleSize, fontWeight: 700, color: theme.muted, marginBottom: 20 }}>{title}</div>
      {children}
    </div>
  );
};

// Two cards side by side, "Marked reachable" and "Marked reachable without
// auth", each with its two runs, then the note on the wrong one; centred.
export const Numbers: React.FC = () => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const title = useEnter(0);
  const sub = useEnter(8);
  const note = useEnter(170);
  const z = wide
    ? { title: 72, sub: 40, card: 46, num: 64, tag: 36, note: 44, gap: 40, pad: "34px 40px", split: false }
    : { title: 68, sub: 36, card: 38, num: 46, tag: 26, note: 34, gap: 24, pad: "24px 26px", split: true };
  return (
    <Scene opacity={fadeOut(frame, durationInFrames - OUT, OUT)}>
      <AbsoluteFill style={{ justifyContent: "center", padding: margin }}>
        <div style={{ display: "flex", flexDirection: wide ? "row" : "column", alignItems: wide ? "baseline" : "flex-start", gap: wide ? 28 : 4 }}>
          <div style={{ fontSize: z.title, fontWeight: 800, ...title }}>{copy.numbersTitle}</div>
          <div style={{ fontSize: z.sub, color: theme.muted, ...sub }}>{copy.numbersCaption}</div>
        </div>
        <div style={{ display: "flex", flexDirection: wide ? "row" : "column", gap: z.gap, marginTop: wide ? 44 : 24 }}>
          <Card at={24} title={copy.reachable} titleSize={z.card} pad={z.pad}>
            <div style={{ display: "flex", flexDirection: wide ? "column" : "row", gap: wide ? 28 : 40 }}>
              <RunClaim c={claim(SHOWN.reachUntouched)} at={34} size={z.num} tagSize={z.tag} split={z.split} />
              <RunClaim c={claim(SHOWN.reachLater)} at={50} size={z.num} tagSize={z.tag} split={z.split} />
            </div>
          </Card>
          <Card at={90} title={copy.withoutAuth} titleSize={z.card} pad={z.pad}>
            <div style={{ display: "flex", flexDirection: wide ? "column" : "row", gap: wide ? 28 : 40 }}>
              <RunClaim c={claim(SHOWN.unauthUntouched)} at={100} tag={copy.before} size={z.num} tagSize={z.tag} split={z.split} />
              <RunClaim c={claim(SHOWN.unauthLater)} at={130} tag={copy.after} size={z.num} tagSize={z.tag} split={z.split} />
            </div>
          </Card>
        </div>
        <div style={{ marginTop: wide ? 40 : 24, fontSize: z.note, lineHeight: 1.3, ...note,
          opacity: frame < 170 ? 0 : Number(note.opacity) }}>{copy.wrongOne}</div>
      </AbsoluteFill>
    </Scene>
  );
};
