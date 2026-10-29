import React from "react";
import { Composition, Series } from "remotion";
import { CallPath, Hook, Numbers, Outro, Terminal, Why } from "./scenes";
import { FPS, SCENES, SIZE, TOTAL } from "./theme";

export const Promo: React.FC = () => (
  <Series>
    <Series.Sequence name="Hook" durationInFrames={SCENES.hook}><Hook /></Series.Sequence>
    <Series.Sequence name="Terminal" durationInFrames={SCENES.terminal}><Terminal /></Series.Sequence>
    <Series.Sequence name="Call path" durationInFrames={SCENES.path}><CallPath /></Series.Sequence>
    <Series.Sequence name="Why" durationInFrames={SCENES.why}><Why /></Series.Sequence>
    <Series.Sequence name="Numbers" durationInFrames={SCENES.numbers}><Numbers /></Series.Sequence>
    <Series.Sequence name="Outro" durationInFrames={SCENES.outro}><Outro /></Series.Sequence>
  </Series>
);

export const RemotionRoot: React.FC = () => (
  <Composition id="GitTracePromo" component={Promo} durationInFrames={TOTAL} fps={FPS} width={SIZE} height={SIZE} />
);
