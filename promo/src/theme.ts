// Dark background, one accent (structure) plus red (danger). Body text is at
// least ~48px so it reads on a phone; key content stays 80px from the sides.
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

export const FPS = 30;
export const SIZE = 1080;
export const FADE = 15;

// Scene lengths in frames: the storyboard's windows (5, 9, 18, 16, 14, 8 s),
// each scene before a transition lengthened by the FADE it shares with the
// next, so the video is exactly 70 s.
export const SCENES = {
  hook: 5 * FPS + FADE,
  terminal: 9 * FPS + FADE,
  path: 18 * FPS + FADE,
  why: 16 * FPS + FADE,
  numbers: 14 * FPS + FADE,
  outro: 8 * FPS,
};
export const TOTAL = Object.values(SCENES).reduce((a, b) => a + b, 0) - 5 * FADE;
