// The install command exactly as the repository README gives it.
import readme from "../../../README.md";

const line = readme.split(/\r?\n/).find((l) => l.startsWith("pipx install git+"));
if (!line) {
  throw new Error("README.md has no `pipx install git+...` line");
}
export const INSTALL = line.split("#")[0].trim();
