/**
 * Note: When using the Node.JS APIs, the config file
 * doesn't apply. Instead, pass options directly to the APIs.
 *
 * All configuration options: https://remotion.dev/docs/config
 */

import { Config } from "@remotion/cli/config";

Config.setRspack(true);
// PNG frames: with JPEG frames the H.264 output is full-range yuvj420p, not yuv420p.
Config.setVideoImageFormat("png");
Config.setPixelFormat("yuv420p");
Config.setOverwriteOutput(true);
Config.setDefaultPremountInSeconds(2);

// The outro's install command is read from the repository README at build
// time (src/data/install.ts): import *.md files as plain text.
Config.overrideRspackConfig((config) => ({
  ...config,
  module: {
    ...config.module,
    rules: [...(config.module?.rules ?? []), { test: /\.md$/, type: "asset/source" }],
  },
}));
