import React from "react";
import { useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { fadeOut, Scene, useEnter } from "../components/ui";

const CARD_AT = [40, 140, 240];
const KEEP_AT = 345;

const cardStyle = (font: number): React.CSSProperties => ({
  background: theme.panel, border: `2px solid ${theme.line}`, borderLeft: `10px solid ${theme.accent}`,
  borderRadius: 22, fontWeight: 700, lineHeight: 1.2, boxShadow: "0 24px 70px rgba(0,0,0,0.4)", fontSize: font,
});

// Square: one card at a time in the middle, then the closing line.
const SquareCard: React.FC<{ text: string; at: number; until: number }> = ({ text, at, until }) => {
  const frame = useCurrentFrame();
  const enter = useEnter(at, 60);
  return (
    <div style={{ position: "absolute", top: 380, left: theme.side, right: theme.side, ...enter,
      opacity: (frame < at ? 0 : Number(enter.opacity)) * fadeOut(frame, until) }}>
      <div style={{ ...cardStyle(56), padding: "50px 46px" }}>{text}</div>
    </div>
  );
};

// Wide: the three cards side by side, each revealed in turn; they stay, and
// the closing line appears under them.
const WideCard: React.FC<{ text: string; at: number }> = ({ text, at }) => {
  const frame = useCurrentFrame();
  const enter = useEnter(at, 60);
  return (
    <div style={{ flex: 1, ...enter, opacity: frame < at ? 0 : Number(enter.opacity) }}>
      <div style={{ ...cardStyle(44), padding: "40px 36px", height: "100%", boxSizing: "border-box" }}>{text}</div>
    </div>
  );
};

export const Why: React.FC = () => {
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const title = useEnter(0);
  const keep = useEnter(KEEP_AT);
  if (wide) {
    return (
      <Scene>
        <div style={{ position: "absolute", top: margin, left: margin, right: margin, textAlign: "center",
          fontSize: 68, fontWeight: 800, ...title }}>{copy.why}</div>
        <div style={{ position: "absolute", top: 250, left: margin, right: margin, height: 380, display: "flex", gap: 36 }}>
          {copy.cards.map((c, i) => <WideCard key={c} text={c} at={CARD_AT[i]} />)}
        </div>
        <div style={{ position: "absolute", top: 700, left: margin + 80, right: margin + 80, textAlign: "center",
          fontSize: 52, fontWeight: 700, lineHeight: 1.25, ...keep }}>{copy.keep}</div>
      </Scene>
    );
  }
  return (
    <Scene>
      <div style={{ position: "absolute", top: 110, left: theme.side, right: theme.side, textAlign: "center",
        fontSize: 66, fontWeight: 800, lineHeight: 1.15, ...title }}>{copy.why}</div>
      {copy.cards.map((c, i) => (
        <SquareCard key={c} text={c} at={CARD_AT[i]} until={(CARD_AT[i + 1] ?? KEEP_AT) - 14} />
      ))}
      <div style={{ position: "absolute", top: 390, left: theme.side, right: theme.side, textAlign: "center",
        fontSize: 58, fontWeight: 700, lineHeight: 1.25, ...keep }}>{copy.keep}</div>
    </Scene>
  );
};
