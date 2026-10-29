// Every sentence on screen. No digits here: numbers come only from
// eval/claims.json (data/claims.ts) and the real scan (data/scan.ts);
// scripts/check-claims.mjs fails if a digit appears in this file.
export const copy = {
  hook: "You built it with AI. Do you know what an attacker can reach?",
  terminalTitle: "No Docker. No database. One command.",
  pathCaption: "Not ‘there might be a bug.’ A path from the outside to the bug.",
  roles: { route: "route", handler: "handler", calls: "calls", sink: "dangerous sink" },
  noAuth: "NO AUTH",
  why: "Why use it next to ChatGPT or Claude?",
  cards: [
    "Same answer every run: it walks a real call graph, it doesn’t guess.",
    "Shows its evidence: the exact path from route to sink.",
    "Runs locally. The no-LLM scan sends your code nowhere.",
  ],
  keep: "Keep your AI assistant for writing and fixing code. Use GitTrace to see what’s actually exposed.",
  numbersTitle: "The honest numbers",
  numbersCaption: "Checked against hand-written ground truth.",
  reachable: "Marked reachable",
  withoutAuth: "Marked reachable without auth",
  marked: "marked",
  wrong: "wrong",
  before: "before",
  after: "after",
  wrongOne: "The wrong one: POST /search. Its token check sits inside the handler.",
  limitTitle: "Known limit",
  limit: "Dynamic dispatch is not resolved yet: handlers that vulnpy looks up with import_module and getattr stay unreached.",
  tagline: "See the dangerous code a route can actually reach.",
  repo: "github.com/codingwinterz/GitTrace",
};
