# GitTrace promo video

A 70-second promo (30 fps, 2100 frames) made with
[Remotion](https://www.remotion.dev), in two formats from one storyboard:
`GitTrace16x9` (1920x1080, the main one) and `GitTrace` (1080x1080). One
component per scene in `src/scenes/`, the arrangement chosen by
`src/layout.tsx`. Silent, with burned-in text; no music and no other
company's logo.

Scenes: hook (4.5 s), terminal (11 s), call path (15 s), why (13.5 s),
numbers (9 s), known limit (6 s), outro (11 s), from `src/timing.json`. The
first four are joined by spring-eased crossfades; the known limit has no
crossfade on either side (Numbers and Limit fade their own content over the
shared background), so the card is fully visible for 4.73 s. The video fades
in from black and out to black over 0.5 s.

## Render

From the repository root:

```bash
cd promo
npm install
npm run check
npx remotion render GitTrace16x9 out/gittrace_promo_1920x1080.mp4 --codec h264 --pixel-format yuv420p
npx remotion render GitTrace out/gittrace_promo_1080.mp4 --codec h264 --pixel-format yuv420p
```

`npm run render` renders the square one after running the check. The MP4s
land in `promo/out/` (ignored by git). `npx remotion studio` opens the preview.

## Where everything on screen comes from

Nothing is typed by hand; it is read when the video is built or rendered.

| On screen | Source |
|---|---|
| The four "`label`: N marked, M wrong" lines | `../eval/claims.json`, imported by `src/data/claims.ts` and looked up by claim_id: `eval-reach-untouched`, `eval-reach-after-reachability`, `eval-unauth-untouched`, `eval-unauth-after-reachability`. They fade in at their final values (no counting up). The repo's `tests/test_claims.py` recounts those records from the results files. |
| The terminal replay | `public/scan_output.txt` (square) and `public/scan_output_90.txt` (wide): the real stdout of GitTrace 2.1.0, installed in a fresh venv from the checkout, running `gittrace scan sample_app --no-llm --no-blame --fail-on none` with `COLUMNS=60` / `COLUMNS=90` and `NO_COLOR=1` on a copy of `tests/fixtures/sample_app` in a neutral folder. The video shows the summary panel and the critical findings (1–7), in order and unedited, except that the panel's block-letter counts are shown as one plain line, "13 findings · 7 critical", whose numbers come from `public/scan_result.json`. |
| The call path | `public/scan_result.json`: the same scan with `--format json`; finding `app/utils/shell.py::8::9` (`os.system`), route `GET /api/users/{name}/files` (`src/data/scan.ts`). |
| The install command | the first `pipx install "git+...@v<version>"` line of `../README.md`, without its comment (`src/data/install.ts`). |
| The known limit | `src/copy.ts` (`limit`). |

The sentences are in `src/copy.ts`, which may not contain a digit.

## Check

```bash
npm run check
```

`scripts/check-claims.mjs` fails on any of these:

- a shown claim_id is not a record in `eval/claims.json`, or `eval/claims.py`
  finds a record that no longer matches its results;
- a digit is hand-typed in `src/copy.ts` or in JSX text, or a scene changes a
  claim's marked/wrong before showing it (a count-up);
- the scan files in `public/` are not the captured scan, the drawn route is
  not in it, or the panel's printed counts disagree with `scan_result.json`;
- the README's install line is not tagged `v` + `gittrace.__version__`;
- the known limit is fully visible for less than 4 s, or a crossfade touches it;
- the bundle does not build, or either composition is not at its size, 30 fps
  and about 70 s (`npx remotion compositions`).

## Recapture the scan

With GitTrace installed from this checkout, on a copy of the fixture:

```bash
cp -r tests/fixtures/sample_app /some/neutral/folder/sample_app && cd /some/neutral/folder
COLUMNS=60 NO_COLOR=1 gittrace scan sample_app --no-llm --no-blame --fail-on none > scan_output.txt
COLUMNS=90 NO_COLOR=1 gittrace scan sample_app --no-llm --no-blame --fail-on none > scan_output_90.txt
gittrace scan sample_app --no-llm --no-blame --fail-on none --format json > scan_result.json
```

Then copy the three files into `promo/public/` and check them for local paths,
names and keys before committing.
