# GitTrace promo video

A 50-second square (1080×1080, 30 fps) promo, made with [Remotion](https://www.remotion.dev).
Silent, with burned-in text; no music and no other company's logo.

## Render

```bash
cd promo
npm install
npm run render        # = data + check + remotion render -> out/gittrace_promo_1080.mp4
```

`npm run render` regenerates the data, runs the number check, then renders
`out/gittrace_promo_1080.mp4` (`out/` is not committed). `npx remotion studio`
opens the preview.

## Where everything on screen comes from

Nothing is typed by hand. `scripts/build-data.mjs` writes `src/data.generated.json` from:

| On screen | Source |
|---|---|
| The four "`label`: N marked, M wrong" tiles | `../eval/claims.json`, by claim_id (`eval-reach-untouched`, `eval-reach-after-reachability`, `eval-unauth-untouched`, `eval-unauth-after-reachability`); those records are themselves checked against the results files by `tests/test_claims.py` |
| The terminal replay | `assets/scan_output.txt`: the real stdout of `gittrace scan bad --no-llm --no-blame --fail-on none`, run with `COLUMNS=60 NO_COLOR=1` in a checkout of fportantier/vulpy at the eval commit (target vulpy-bad). The video shows two contiguous slices of it, unedited and in order |
| The call path | `assets/scan_result.json`: the same scan with `--format json`; finding `libuser.py::12::12`, route `GET /user/login` |
| The install command | the README's `pipx install git+...` line |

The sentences are in `src/copy.ts`, which may not contain a digit.

## Check

```bash
npm run check
```

`scripts/check-numbers.mjs` fails if the generated data is out of date, if a
shown claim differs from its `eval/claims.json` record (label, dimension,
marked, wrong, source file), if any digit is hand-typed in `src/copy.ts` or in
JSX text, or if the terminal lines are not contiguous runs of the real output.

## Recapture the scan

From a checkout of vulpy at the commit in `../eval/targets.json`:

```bash
COLUMNS=60 NO_COLOR=1 gittrace scan bad --no-llm --no-blame --fail-on none > promo/assets/scan_output.txt
gittrace scan bad --no-llm --no-blame --fail-on none --format json > promo/assets/scan_result.json
npm run data
```
