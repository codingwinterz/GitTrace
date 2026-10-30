// Dark background, one accent (structure) plus red (danger). In the wide
// video body text is at least 40px and captions at least 36px; key content
// stays 96px (wide) or 80px (square) from the edges.
import timing from "./timing.json";

export const theme = {
  bg: "#0a0e16",
  panel: "#121a28",
  line: "#233047",
  text: "#eef2f8",
  muted: "#97a3b8",
  accent: "#8fb2ff",
  danger: "#ff4d5e",
  sans: "'Segoe UI', Inter, Arial, sans-serif",
  mono: "'Cascadia Mono', Consolas, 'Courier New', monospace",
  side: 80,
};

// Timing lives in timing.json so scripts/check-claims.mjs can check it too.
export const FPS = timing.fps;
export const SIZE = 1080;
export const FADE = timing.fade;
export const EDGE_FADE = timing.edgeFade;
export const LIMIT = timing.limit;

type SceneName = keyof typeof timing.windowsSeconds;
const crossfades = timing.crossfadeAfter as SceneName[];

// Scene lengths in frames: each scene's on-screen window, lengthened by the
// FADE it shares with the next scene when a crossfade follows it. The known
// limit has no crossfade on either side: Numbers and Limit fade their own
// content out over the steady background, so the card is never under another
// scene.
export const SCENES = Object.fromEntries(
  (Object.keys(timing.windowsSeconds) as SceneName[]).map((k) => [
    k, Math.round(timing.windowsSeconds[k] * FPS) + (crossfades.includes(k) ? FADE : 0),
  ]),
) as Record<SceneName, number>;
export const TOTAL = Object.values(SCENES).reduce((a, b) => a + b, 0) - crossfades.length * FADE;
