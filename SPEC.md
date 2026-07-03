# LATENT — build contract (v1)

Latent scans your machine locally, finds work you keep doing by hand that AI can already do,
and shows a receipt-backed report: hours/week leaking, a Leverage Score, and one-click
automation briefs. 100% local. Pure Node stdlib. No external npm deps anywhere.

## Files (all under `latent/`)
- `scanner.js` — CLI + module. `node scanner.js [--roots=a,b] [--out=scan.json]`.
  Exports `runScan(opts, onProgress)` (async → scan object) and `DETECTORS`, `ESTIMATES`.
- `server.js`  — node:http server, port **8820** (env PORT overrides). Serves `public/` + API.
- `public/index.html` — single-file React 18 UMD + Babel Standalone frontend. THE product.
- `playbooks/` — generated automation briefs (`playbooks/<findingId>/BRIEF.md`).
- `scan.json` — cached scan output (gitignore-style: regenerated any time).
- `README.md` — run + philosophy ("advice is slop; receipts + a button are not").

## Scan object schema (single source of truth)
```json
{
  "generatedAt": "ISO", "roots": ["abs paths"], 
  "stats": {"files":0,"dirs":0,"repos":0,"textFilesSampled":0,"durationMs":0,"skipped":0},
  "score": {"value": 34, "recoverableHoursPerWeek": 8.6,
            "methodology": "score = clamp(round(100 - 9*hours), 4, 96); hours = sum of per-finding estimates, each capped; formulas in ESTIMATES table"},
  "findings": [{
    "id": "version-chains:ab12cd",         
    "detector": "version-chains",
    "title": "You version files by hand",   
    "summary": "1–2 sentences, second person, plain, factual.",
    "evidence": [{"path":"/abs/path","detail":"7 versions, report_v1.md → report_final_FINAL.md","mtime":"ISO"}],
    "metrics": {"count":7,"estMinutesPerInstance":4,"estHoursPerWeek":0.6,"confidence":0.85,"oneShot":false},
    "automation": {"kind":"recurring-draft","title":"Recurring draft agent",
                   "status":"idle","briefPath":null}
  }]
}
```
- findings sorted by `estHoursPerWeek` desc. Cap displayed list at 12 (scanner may emit more).
- IDs: `<detector>:<8-char fnv1a hex of joined evidence paths>`. **fnv1a MUST use `>>>` (unsigned).**

## Detectors (scanner.js) — each returns findings[]
Walk once, collect a file index (path, size, mtime, ext, dir, isRepo markers), then run detectors
over the index. Per-file text reads only for whitelisted exts (.md .txt .csv .json ≤200KB).
1. **version-chains** — same-dir filename groups differing only by version tokens
   (`v\d+`, `final`, `copy`, `(1)`, dates, `draft`, `old`, `new`, trailing digits). len≥3 → finding.
   Est: (len-1)×4min spread over chain mtime span (min 1wk). Cap 1.5 h/wk.
2. **dated-recurrence** — same-dir name-template series with embedded dates (YYYY-MM-DD, YYYYMMDD,
   MM-DD etc.), ≥4 instances, near-regular period (cv < 0.6). Est: instances_per_week × 45min (text)
   or 25min. Cap 3.0. THE flagship — automation.kind "recurring-draft".
3. **near-duplicate-text** — .md/.txt files 0.5–200KB: 5-word shingles, Jaccard ≥ 0.7 clusters
   (size≥3, cross-file, same root). Est: (size-1)×12min over span. Cap 2.0.
4. **untested-repos** — dirs containing `.git` with ≥8 source files (.js .ts .py .go .rs .tsx)
   and zero test files/dirs (test|spec|__tests__). Est one-shot 2.5h ÷ 8wk. Cap 1.5. oneShot:true.
5. **undocumented-repos** — repos with code but no README or README < 300 bytes. 40min ÷ 8wk each. Cap 0.5. oneShot.
6. **screenshot-pileup** — `Screenshot*`/`Screen Recording*`/`SCR-*` in Desktop/Downloads, ≥15 files.
   Est: count×20s over span. Cap 0.3.
7. **downloads-entropy** — Downloads root: >60 loose files → 15min/wk + 5min/100 files. Cap 0.8.
8. **commit-drudgery** — per repo, `git log --pretty=%s -n 300` (execFile, 3s timeout, skip on error):
   share of messages that are tiny/generic (`fix|wip|update|typo|.` or len<8) ≥ 40% and ≥30 commits.
   Est: rate×commits/wk×2min. Cap 0.5.
9. **csv-report-assembly** — same-dir .csv series sharing identical header row, ≥4 files. Like #2. Cap 2.0.
10. **scaffold-repetition** — ≥3 non-git project dirs sharing same boilerplate fileset signature
    (e.g. {index.html, style.css} or {package.json, index.js}). 35min ÷ 8wk. Cap 0.7.

Walker rules: default roots `[$HOME/Downloads, $HOME/Desktop, $HOME/Documents]` plus common
code dirs ($HOME/{Projects,projects,Developer,dev,code,repos,workspace}) — existing only. EXCLUDE dirs: node_modules, .git (contents; still note repo), Library, .cache, .npm,
.Trash, venv, __pycache__, dist, build, .next. Depth ≤ 7, ≤ 60k files, follow no symlinks.
EVERY fs call wrapped: EPERM/EACCES/ENOENT → count in stats.skipped, never throw.
onProgress({phase:"walking"|"analyzing"|"done", filesSeen, dirsSeen, currentPath}) throttled ~100ms.

## server.js — API
- `GET  /api/scan`      → cached scan.json (404 `{error:"no scan yet"}` if absent).
- `POST /api/scan`      → 202 `{started:true}`; kicks async runScan (one at a time; 409 if running);
                          writes scan.json when done. Body optional `{roots:[...]}` (≤100KB cap).
- `GET  /api/progress`  → latest progress object + `{running:bool}`.
- `POST /api/automate`  → body `{findingId}`. Loads scan.json, finds finding, renders BRIEF.md
  (template below) to `playbooks/<findingId>/BRIEF.md`, sets automation.status="briefed",
  automation.briefPath, persists scan.json, returns `{brief, briefPath}`. 404 unknown id.
- `GET  /api/brief?id=` → `{brief}` text.
- Static: `public/`, index fallback, `..` traversal guard, correct MIME (html/js/css/svg/png/json/woff2).

BRIEF.md template (fill from finding):
```
# Automation brief — {title}
Generated by Latent {generatedAt}. Status: DRAFT-ONLY. Never send/submit/push; write artifacts to ./out/.
## What keeps happening
{summary}
## Evidence
{evidence rows: - path — detail}
## Your task
{per automation.kind: recurring-draft → "Detect the newest instance's inputs, produce next instance as a draft in ./out/";
 test-writer → "Write a test suite for this repo; put a plan in ./out/PLAN.md first"; etc.}
## Constraints
- Draft only. All output inside {playbookDir}/out/. Do not modify the evidence files.
- Leave a RECEIPT.md: what you read, what you produced.
Run it: `cd {playbookDir} && claude -p "$(cat BRIEF.md)"`
```

## Frontend (public/index.html) — the spectacular part
**Identity: a thermal instrument reading your machine. Heat = hours leaking. Cold = handled.**
NOT: cream+terracotta editorial, near-black+acid-green, broadsheet hairlines, generic admin dashboard.

Tokens (CSS vars):
- `--carbon:#0E0C0A` bg (warm near-black) · `--soot:#1A1512` panels · `--seam:#2A211B` borders
- `--bone:#EDE6DC` ink · `--ash:#9C8F80` muted
- Heat ramp (data ONLY): `--ember:#FF7A1A` → `--magma:#FF3D5E` (gradient on hot numbers/bars)
- `--glacier:#7ED7FF` — ONLY for automated/reclaimed/briefed states (cold = handled). Never decorative.
Type: display **Bricolage Grotesque** (700/800, tight leading, used sparingly & large);
body **Archivo** (400/500); data/paths/numbers **IBM Plex Mono**. Google Fonts link + system fallbacks.
CSS vars `--font-display/--font-sans/--font-mono`.

States & choreography (React state machine: idle → scanning → reveal → report):
1. **idle** — near-empty screen. Wordmark "LATENT" small. Center: one line display type
   "Your machine knows what you should automate." Sub (mono): roots list. One button: "Read my machine".
2. **scanning** — the instrument: giant mono file counter ticking (real /api/progress polling, 400ms),
   current path streaming in a single mono line (truncate middle), thin heat-gradient trace line
   growing across screen width by files/60k. No spinners.
3. **reveal** (on scan done; ~4s orchestrated, skippable on click, skipped when prefers-reduced-motion):
   a. mono: "{files} files · {repos} repos · {duration}s" fades in/up.
   b. THE NUMBER: recoverable hrs/week counts up in display type ~96-140px, heat-gradient text
      (background-clip), from 0 to value with ease-out; label under it (mono, small):
      "hours/week you're doing by hand that AI can already do".
   c. score stamps in beside/below: "LEVERAGE {value}/100" with a stamp thunk (scale 1.15→1).
   d. receipt cards stagger in 60ms apart.
4. **report** — sticky top bar (wordmark · score · hours · "Rescan" ghost button · "Share card").
   Receipt cards, one column, max-width ~880px:
   - eyebrow (mono): `RECEIPT 01 — VERSION CHAINS` (numbered by hours desc — order = severity, meaningful)
   - title (display, ~28px), summary (body)
   - evidence rows (mono 12.5px, ash): real paths (middle-truncated) + detail + count
   - heat bar: width ∝ estHoursPerWeek / max, heat gradient; est label `~1.4 h/wk` mono
   - button: "Draft the automation" → POST /api/automate → status flips to glacier chip "Brief ready"
     + "View brief" opens modal (mono, pre-wrap, copy button with the `claude -p` run line).
   - oneShot findings label est as `~2.5 h once` instead of h/wk.
5. **Share card**: canvas 1200×630 (explicit width/height attrs — canvas is a replaced element),
   carbon bg, heat number, score, "n receipts", tiny wordmark; download PNG button. This is the viral artifact.
Footer: methodology expander — print score.methodology + per-detector formula list (mono). Honesty is brand.
Empty state (0 findings): "Clean read. Either you're already leveraged — or point me at more roots." + rescan.
Error state: plain explanation + retry button, no mood.

Quality floor: keyboard focusable everything, :focus-visible rings, aria-labels on icon buttons,
prefers-reduced-motion → no count-up/stagger (instant), responsive ≥360px, `color-scheme: dark`.

**Babel Standalone gotcha (MANDATORY):** Babel 8 defaults to automatic JSX runtime which breaks
non-module scripts. Do exactly:
```html
<script>Babel.registerPreset('react-classic',{presets:[[Babel.availablePresets['react'],{runtime:'classic'}]]});</script>
<script type="text/babel" data-presets="react-classic"> /* app */ </script>
```
React/ReactDOM 18 UMD from unpkg. No imports/exports in the babel script. No fetch to external hosts.

## Copy voice
Second person, active, plain, zero hype. Receipts state facts ("You kept 7 hand-made versions of
this file"), buttons say what happens ("Draft the automation"), statuses match ("Brief ready").
Never "unlock", "supercharge", "seamless", no emoji.

## Verification expectations
- `node scanner.js --roots=<fixture> --out=/tmp/x.json` exits 0, valid JSON matching schema,
  detects planted fixtures (version chain, dated series, csv series, untested repo).
- Server: all endpoints respond correctly; automate produces BRIEF.md; static serves index.
- Frontend: renders without console errors against a real scan.json; all 4 states reachable.
