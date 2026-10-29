import React from "react";
import { useCurrentFrame } from "remotion";
import { copy } from "../copy";
import { theme } from "../theme";
import { fadeOut, Scene, useEnter } from "../components/ui";

const CARD_AT = [40, 140, 240];
const KEEP_AT = 345;

const Card: React.FC<{ text: string; at: number; until: number }> = ({ text, at, until }) => {
  const frame = useCurrentFrame();
  const enter = useEnter(at, 60);
  return (
    <div style={{ position: "absolute", top: 380, left: theme.side, right: theme.side, ...enter,
      opacity: (frame < at ? 0 : Number(enter.opacity)) * fadeOut(frame, until) }}>
      <div style={{ background: theme.panel, border: `2px solid ${theme.line}`, borderLeft: `10px solid ${theme.accent}`,
        borderRadius: 22, padding: "50px 46px", fontSize: 56, fontWeight: 700, lineHeight: 1.2,
        boxShadow: "0 24px 70px rgba(0,0,0,0.4)" }}>{text}</div>
    </div>
  );
};

export const Why: React.FC = () => {
  const title = useEnter(0);
  const keep = useEnter(KEEP_AT);
  return (
    <Scene>
      <div style={{ position: "absolute", top: 110, left: theme.side, right: theme.side, textAlign: "center",
        fontSize: 66, fontWeight: 800, lineHeight: 1.15, ...title }}>{copy.why}</div>
      {copy.cards.map((c, i) => (
        <Card key={c} text={c} at={CARD_AT[i]} until={(CARD_AT[i + 1] ?? KEEP_AT) - 14} />
      ))}
      <div style={{ position: "absolute", top: 390, left: theme.side, right: theme.side, textAlign: "center",
        fontSize: 58, fontWeight: 700, lineHeight: 1.25, ...keep }}>{copy.keep}</div>
    </Scene>
  );
};
