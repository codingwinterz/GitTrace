import React from "react";
import { AbsoluteFill } from "remotion";
import { copy } from "../copy";
import { INSTALL } from "../data/install";
import { theme } from "../theme";
import { Scene, useEnter } from "../components/ui";

export const Outro: React.FC = () => {
  const name = useEnter(0);
  const tag = useEnter(10);
  const repo = useEnter(22);
  const cmd = useEnter(34);
  return (
    <Scene>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: theme.side, textAlign: "center" }}>
        <div style={{ fontSize: 104, fontWeight: 900, letterSpacing: -1, ...name }}>GitTrace</div>
        <div style={{ fontSize: 54, fontWeight: 700, marginTop: 18, lineHeight: 1.2, ...tag }}>{copy.tagline}</div>
        <div style={{ fontSize: 50, color: theme.accent, marginTop: 54, fontWeight: 700, ...repo }}>{copy.repo}</div>
        <div style={{ fontFamily: theme.mono, fontSize: 22, marginTop: 40, padding: "14px 16px", borderRadius: 12,
          background: theme.panel, border: `2px solid ${theme.line}`, whiteSpace: "pre", ...cmd }}>{INSTALL}</div>
      </AbsoluteFill>
    </Scene>
  );
};
