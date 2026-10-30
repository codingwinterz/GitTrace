import React from "react";
import { AbsoluteFill } from "remotion";
import { copy } from "../copy";
import { INSTALL } from "../data/install";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { Scene, useEnter } from "../components/ui";

// Name, tagline, repo URL and the README's install command (the command
// only, without the README's comment), centred. The square breaks the command
// before its URL so it fits at a readable size.
export const Outro: React.FC = () => {
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const name = useEnter(0);
  const tag = useEnter(10);
  const repo = useEnter(22);
  const cmd = useEnter(34);
  const command = wide ? INSTALL : INSTALL.replace(/ ("?git\+)/, "\n$1");
  return (
    <Scene>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: margin, textAlign: "center" }}>
        <div style={{ fontSize: wide ? 120 : 104, fontWeight: 900, letterSpacing: -1, ...name }}>GitTrace</div>
        <div style={{ fontSize: wide ? 58 : 54, fontWeight: 700, marginTop: 18, lineHeight: 1.2, ...tag }}>{copy.tagline}</div>
        <div style={{ fontSize: wide ? 56 : 50, color: theme.accent, marginTop: wide ? 50 : 54, fontWeight: 700, ...repo }}>{copy.repo}</div>
        <div style={{ fontFamily: theme.mono, fontSize: wide ? 40 : 26, lineHeight: 1.35, marginTop: 40, padding: wide ? "18px 30px" : "14px 18px", borderRadius: 12,
          background: theme.panel, border: `2px solid ${theme.line}`, whiteSpace: "pre", textAlign: "left", ...cmd }}>{command}</div>
      </AbsoluteFill>
    </Scene>
  );
};
