# GitTrace promo video

A 70-second square promo (1080×1080, 30 fps, 2100 frames), made with
[Remotion](https://www.remotion.dev): composition `GitTrace`, one component
per scene in `src/scenes/`, joined by fades (`@remotion/transitions`).
Silent, with burned-in text; no music and no other company's logo.

## Render

From the repository root:

```bash
cd promo
npm install
npx remotion render GitTrace out/gittrace_promo_1080.mp4
```

`npm run render` does the same after running the check below. The MP4 lands
in `promo/out/gittrace_promo_1080.mp4` (not committed). `npx remotion studio`
opens the preview.

## Where everything on screen comes from

Nothing is typed by hand; it is read when the video is built or rendered.

| On screen | Source |
|---|---|
| The four "`label`: N marked, M wrong" cards | `../eval/claims.json`, imported by `src/data/claims.ts` and looked up by claim_id: `eval-reach-untouched`, `eval-reach-after-reachability`, `eval-unauth-untouched`, `eval-unauth-after-reachability`. The repo's `tests/test_claims.py` recounts those records from the results files. |
| The terminal replay | `public/scan_output.txt`: the real stdout of `gittrace scan bad --no-llm --no-blame --fail-on none`, run with `COLUMNS=60 NO_COLOR=1` in a checkout of fportantier/vulpy at the eval commit (target vulpy-bad). The video shows its first lines (the summary panel and findings 1–3), unedited and in order, then zooms on the findings. |
| The call path | `public/scan_result.json`: the same scan with `--format json`; finding `libuser.py::12::12`, route `GET /user/login` (`src/data/scan.ts`). |
| The install command | the `pipx install git+...` line of `../README.md` (`src/data/install.ts`). |

The sentences are in `src/copy.ts`, which may not contain a digit.

## Check

```bash
npm run check
```

`scripts/check-claims.mjs` fails if a shown claim_id is not a record in
`eval/claims.json`, if `eval/claims.py` finds a record that no longer matches
its results, if a digit is hand-typed in `src/copy.ts` or in JSX text, or if
the scan files in `public/` are not the captured scan.

## Recapture the scan

In a checkout of vulpy at the commit in `../eval/targets.json`:

```bash
COLUMNS=60 NO_COLOR=1 gittrace scan bad --no-llm --no-blame --fail-on none > ../GitTrace/promo/public/scan_output.txt
gittrace scan bad --no-llm --no-blame --fail-on none --format json > ../GitTrace/promo/public/scan_result.json
```
