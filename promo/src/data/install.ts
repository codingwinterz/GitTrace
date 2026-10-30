// The install command exactly as the repository README gives it: the first
// `pipx install git+...@v<version>` line (quoted or not), without its comment.
// scripts/check-claims.mjs checks that the tag is gittrace.__version__.
import readme from "../../../README.md";

export const INSTALL_LINE = /^pipx install "?git\+https:\/\/\S+@v\d+\.\d+\.\d+"?(\s|$)/;

const line = readme.split(/\r?\n/).find((l) => INSTALL_LINE.test(l));
if (!line) {
  throw new Error("README.md has no `pipx install \"git+...@v<version>\"` line");
}
export const INSTALL = line.split("#")[0].trim();
