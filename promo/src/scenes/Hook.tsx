import React from "react";
import { AbsoluteFill } from "remotion";
import { copy } from "../copy";
import { theme } from "../theme";
import { Scene, WordReveal } from "../components/ui";

// "You built it with AI. Do you know what an attacker can reach?" word by word;
// the second sentence in the accent.
export const Hook: React.FC = () => {
  const firstSentence = copy.hook.split(" ").findIndex((w) => w.endsWith("."));
  return (
    <Scene>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", padding: theme.side }}>
        <WordReveal text={copy.hook} at={8} every={5}
          color={(i) => (i > firstSentence ? theme.accent : theme.text)}
          style={{ fontSize: 88, fontWeight: 800, lineHeight: 1.12, textAlign: "center" }} />
      </AbsoluteFill>
    </Scene>
  );
};
