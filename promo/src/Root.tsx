import React from "react";
import { AbsoluteFill, Composition, Easing, interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { springTiming, TransitionSeries } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { Background } from "./components/ui";
import { Layout, LayoutProvider } from "./layout";
import { CallPath } from "./scenes/CallPath";
import { Hook } from "./scenes/Hook";
import { Limit } from "./scenes/Limit";
import { Numbers } from "./scenes/Numbers";
import { Outro } from "./scenes/Outro";
import { Terminal } from "./scenes/Terminal";
import { Why } from "./scenes/Why";
import { EDGE_FADE, FADE, FPS, SCENES, SIZE, TOTAL } from "./theme";

const cut = () => (
  <TransitionSeries.Transition presentation={fade()}
    timing={springTiming({ config: { damping: 200 }, durationInFrames: FADE })} />
);

// Fade in from black at the start and out to black at the end, eased.
const EdgeFade: React.FC = () => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const easing = Easing.inOut(Easing.cubic);
  const opacity = Math.max(
    interpolate(frame, [0, EDGE_FADE], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing }),
    interpolate(frame, [durationInFrames - EDGE_FADE, durationInFrames - 1], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing }),
  );
  return <AbsoluteFill style={{ backgroundColor: "#000", opacity }} />;
};

// One storyboard for both formats; `layout` picks each scene's arrangement.
// The background is drawn once, under every scene, so crossfades and the
// cuts around the known limit only change the foreground.
export const GitTrace: React.FC<{ layout: Layout }> = ({ layout }) => (
  <LayoutProvider layout={layout}>
    <AbsoluteFill>
      <Background />
      <TransitionSeries>
        <TransitionSeries.Sequence name="Hook" durationInFrames={SCENES.hook}><Hook /></TransitionSeries.Sequence>
        {cut()}
        <TransitionSeries.Sequence name="Terminal" durationInFrames={SCENES.terminal}><Terminal /></TransitionSeries.Sequence>
        {cut()}
        <TransitionSeries.Sequence name="Call path" durationInFrames={SCENES.path}><CallPath /></TransitionSeries.Sequence>
        {cut()}
        <TransitionSeries.Sequence name="Why" durationInFrames={SCENES.why}><Why /></TransitionSeries.Sequence>
        {cut()}
        <TransitionSeries.Sequence name="Numbers" durationInFrames={SCENES.numbers}><Numbers /></TransitionSeries.Sequence>
        <TransitionSeries.Sequence name="Limit" durationInFrames={SCENES.limit}><Limit /></TransitionSeries.Sequence>
        <TransitionSeries.Sequence name="Outro" durationInFrames={SCENES.outro}><Outro /></TransitionSeries.Sequence>
      </TransitionSeries>
      <EdgeFade />
    </AbsoluteFill>
  </LayoutProvider>
);

export const RemotionRoot: React.FC = () => (
  <>
    <Composition id="GitTrace" component={GitTrace} durationInFrames={TOTAL} fps={FPS} width={SIZE} height={SIZE}
      defaultProps={{ layout: "square" as Layout }} />
    <Composition id="GitTrace16x9" component={GitTrace} durationInFrames={TOTAL} fps={FPS} width={1920} height={1080}
      defaultProps={{ layout: "wide" as Layout }} />
  </>
);
