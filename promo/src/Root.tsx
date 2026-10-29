import React from "react";
import { Composition } from "remotion";
import { linearTiming, TransitionSeries } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { Layout, LayoutProvider } from "./layout";
import { CallPath } from "./scenes/CallPath";
import { Hook } from "./scenes/Hook";
import { Numbers } from "./scenes/Numbers";
import { Outro } from "./scenes/Outro";
import { Terminal } from "./scenes/Terminal";
import { Why } from "./scenes/Why";
import { FADE, FPS, SCENES, SIZE, TOTAL } from "./theme";

const cut = () => <TransitionSeries.Transition presentation={fade()} timing={linearTiming({ durationInFrames: FADE })} />;

// One storyboard for both formats; `layout` picks each scene's arrangement.
export const GitTrace: React.FC<{ layout: Layout }> = ({ layout }) => (
  <LayoutProvider layout={layout}>
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
      {cut()}
      <TransitionSeries.Sequence name="Outro" durationInFrames={SCENES.outro}><Outro /></TransitionSeries.Sequence>
    </TransitionSeries>
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
