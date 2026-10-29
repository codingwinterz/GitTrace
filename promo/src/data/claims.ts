// The only way a number reaches the screen. eval/claims.json is imported
// directly, so the bundler reads it every time the video is built or
// rendered; each record is recounted from the results files by the repo's
// tests/test_claims.py. A claim_id that is not in the file throws.
import claimsFile from "../../../eval/claims.json";

export type Claim = {
  claim_id: string;
  doc: string;
  label: string;
  dimension: "reachable" | "unauthenticated";
  marked: number;
  wrong: number;
  source_file: string;
};

const records = claimsFile.claims as Claim[];

export const claim = (id: string): Claim => {
  const found = records.find((c) => c.claim_id === id);
  if (!found) {
    throw new Error(`claim ${id} is not in eval/claims.json`);
  }
  return found;
};

// The claims the video shows, by claim_id (scripts/check-claims.mjs reads this list).
export const SHOWN = {
  reachUntouched: "eval-reach-untouched",
  reachLater: "eval-reach-after-reachability",
  unauthUntouched: "eval-unauth-untouched",
  unauthLater: "eval-unauth-after-reachability",
} as const;
