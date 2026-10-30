import React from "react";
import { AbsoluteFill, Easing, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { copy } from "../copy";
import { useLayout, useMargin } from "../layout";
import { LIMIT, theme } from "../theme";
import { fadeOut, Scene } from "../components/ui";

// The known limit, on its own: no crossfade on either side (Root.tsx), so the
// card is fully visible from LIMIT.inEnd until it fades out over the last
// LIMIT.outLength frames; scripts/check-claims.mjs checks that this is at
// least four seconds.
export const Limit: React.FC = () => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const wide = useLayout() === "wide";
  const margin = useMargin();
  const p = interpolate(frame, [LIMIT.inStart, LIMIT.inEnd], [0, 1],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.out(Easing.cubic) });
  const opacity = p * fadeOut(frame, durationInFrames - LIMIT.outLength, LIMIT.outLength);
  return (
    <Scene opacity={opacity}>
      <AbsoluteFill style={{ justifyContent: "center", padding: margin }}>
        <div style={{ transform: `translateY(${(1 - p) * 40}px)`, background: theme.panel, border: `2px solid ${theme.line}`,
          borderLeft: `12px solid ${theme.danger}`, borderRadius: 24, padding: wide ? "56px 64px" : "40px 44px",
          boxShadow: "0 24px 70px rgba(0,0,0,0.4)" }}>
          <div style={{ fontSize: wide ? 48 : 40, fontWeight: 800, color: theme.danger, textTransform: "uppercase", letterSpacing: 3 }}>{copy.limitTitle}</div>
          <div style={{ marginTop: 20, fontSize: wide ? 60 : 52, fontWeight: 700, lineHeight: 1.25 }}>{copy.limit}</div>
        </div>
      </AbsoluteFill>
    </Scene>
  );
};
