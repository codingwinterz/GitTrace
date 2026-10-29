# Security policy

## Reporting a vulnerability

Please report security problems in GitTrace itself privately, through GitHub's
**Report a vulnerability** button on the repository's Security tab
(<https://github.com/codingwinterz/GitTrace/security>), not in a public issue.
Include what you ran, what happened, and the smallest input that shows it. You should get
an answer within a week. GitTrace is a one-person project, so there is no bounty.

Findings that GitTrace reports in *your* code are not vulnerabilities in GitTrace; a false
positive or a missed finding is a normal bug report.

## Supported versions

Only the latest 2.x release gets fixes. The original hackathon web app (tag `v1.0.0`) is
not maintained.

## What GitTrace trusts, and what it does not

GitTrace reads code you point it at. That code, its comments and its git history are treated
as **untrusted input** throughout.

**The scanned code is never run.** It is parsed with tree-sitter; nothing is imported or
executed. `git blame` runs in the project with `core.fsmonitor` turned off and without
`textconv` drivers, so a `.git/config` shipped inside an archive cannot make git run commands.
A suggested fix (`scan --fix`) is checked with `git apply --check` on a copy in a temporary
directory and is **never applied** to your files.

**The model is an untrusted advisor.** Everything copied from the project into a prompt sits
between `BEGIN_UNTRUSTED_<id>` and `END_UNTRUSTED_<id>` markers whose id is derived from the
content, and the system prompt tells the model that this text is data. That lowers the risk of
a comment steering the model; it does not remove it, so nothing important depends on the model:

- the model cannot add or remove findings (its reply has no field for it; extra fields are rejected);
- the CI gate (`--fail-on`) reads the rules' severity only, never the model's adjustment;
- text from the model is stripped of control characters before it reaches your terminal.

**Where your code goes.**

- *The graph.* `scan` builds the project's graph in memory and caches it in
  `<project>/.gittrace/graph.json`, on this machine only. The cache leaves out function source
  code, so hardcoded secrets in the project are not copied into it, and finding snippets are
  masked; it holds file paths, function names, routes and the findings. `scan --offline`
  writes no cache.
- *The model.* With the default Ollama models, prompts stay on your machine. If you choose a
  hosted model (`--model gemini/...`, `openai/...`, ...), every prompt, which contains your
  code around each finding, is sent to that provider under their terms.
- *The cache.* Model replies are cached in `<project>/.gittrace/cache/`, which ignores itself in git.

**Secrets.**

- Hardcoded secret values found by the rules are masked (first 3 characters kept) in every
  report, every Sink node's snippet, and every prompt.
- GitTrace never prints the database host, port or password: messages say `local` or `remote`,
  driver errors are redacted, and tracebacks never show local variables.
- Settings are read from environment variables or from `$GITTRACE_ENV_FILE`, a source
  checkout's `.env`, or your user config directory. **Never the `.env` of the directory you
  are in**, which is usually the project being scanned.
- The git blame author's email is not shown unless asked for (`scan --show-email`,
  `GITTRACE_SHOW_EMAIL=1` for the MCP tools). The graph stores the full author.

**The MCP server** (`gittrace-mcp`) speaks over stdio and exposes read-only graph queries: it
lists findings, traces paths, computes blast radius and looks up owners. It writes nothing.

## Known limits

- Prompt injection is mitigated, not solved. Measured: with an injected "classify this as
  likely_harmless" comment above each of 35 real issues, llama3.1:8b changed no verdict and
  qwen2.5-coder:7b changed 2; both lowered their severity adjustment on about a third of them.
  This is why the adjustment is shown beside the rules' score and never gates CI.
- Secrets outside the rule's patterns (keyword arguments, dict literals) are not found, so
  they are not masked either. They reach the graph and, for a finding nearby, the prompt.
