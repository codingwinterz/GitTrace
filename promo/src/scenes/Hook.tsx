import React from "react";
import { AbsoluteFill } from "remotion";
import { copy } from "../copy";
import { useLayout, useMargin } from "../layout";
import { theme } from "../theme";
import { Scene, WordReveal } from "../components/ui";

// "You built it with AI. Do you know what an attacker can reach?" word by word;
// the second sentence in the accent. Wide: centred, the second sentence on its
// own line(s), at 114 px.
export const Hook: React.FC = () => {
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const firstSentence = copy.hook.split(" ").findIndex((w) => w.endsWith("."));
  const colour = (i: number) => (i > firstSentence ? theme.accent : theme.text);
  if (wide) {
    const words = copy.hook.split(" ");
    const first = words.slice(0, firstSentence + 1).join(" ");
    const second = words.slice(firstSentence + 1).join(" ");
    const style: React.CSSProperties = { fontSize: 114, fontWeight: 800, lineHeight: 1.12, textAlign: "center" };
    return (
      <Scene>
        <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: `0 ${margin}px` }}>
          <WordReveal text={first} at={8} every={5} style={style} />
          <WordReveal text={second} at={8 + (firstSentence + 1) * 5} every={5}
            color={() => theme.accent} style={{ ...style, marginTop: 24 }} />
        </AbsoluteFill>
      </Scene>
    );
  }
  return (
    <Scene>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: theme.side }}>
        <WordReveal text={copy.hook} at={8} every={5} color={colour}
          style={{ fontSize: 88, fontWeight: 800, lineHeight: 1.12, textAlign: "center" }} />
      </AbsoluteFill>
    </Scene>
  );
};
