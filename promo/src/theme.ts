// One dark background, one accent. Sizes follow the 1080px-wide minimums
// (headline >= 84px, supporting text >= 44px) and an 80px side safe area.
export const theme = {
  bg: "#0b0f17",
  panel: "#131a26",
  line: "#263043",
  text: "#e9eef6",
  muted: "#93a0b4",
  accent: "#ff4d5e",
  sans: "'Segoe UI', 'Inter', Arial, sans-serif",
  mono: "'Cascadia Mono', Consolas, 'Courier New', monospace",
  side: 80,
};

export const FPS = 30;
export const SIZE = 1080;
// Scene lengths in frames (the storyboard's seconds at 30 fps).
export const SCENES = {
  hook: 4 * FPS,
  terminal: 6 * FPS,
  path: 14 * FPS,
  why: 12 * FPS,
  numbers: 10 * FPS,
  outro: 4 * FPS,
};
export const TOTAL = Object.values(SCENES).reduce((a, b) => a + b, 0);
