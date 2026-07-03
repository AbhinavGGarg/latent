# Latent

**Your machine knows what you should automate. Latent reads it and shows you — with receipts.**

Latent scans your computer locally, finds the work you keep doing by hand that AI can
already do, and gives you three things:

1. **Receipts** — real evidence, not vibes: "you kept 7 hand-made copies of `report.pdf`
   in Downloads", "2 repos, 20 source files, 0 tests", with the actual paths.
2. **A number** — estimated hours/week you're leaking, plus a Leverage Score out of 100.
   Every estimate traces to a visible formula. If we can't show the math, we don't show the number.
3. **A button** — each receipt drafts a ready-to-run agent brief (`playbooks/<id>/BRIEF.md`)
   with the evidence baked in. Run it with the `claude -p` one-liner in the modal; artifacts
   land in `out/` with a `RECEIPT.md` of what the agent read and produced.

## Run it

```
node server.js
```

Open http://localhost:8820 and press **Read my machine**. That's it — pure Node stdlib,
nothing to install, no build step.

By default it reads `~/Downloads`, `~/Desktop`, `~/Documents`, and common code folders
(`~/Projects`, `~/dev`, `~/code`, ...) that exist. Point it elsewhere:
`node scanner.js --roots=/path/a,/path/b --out=scan.json`

## Running the automations without prompt fatigue

Every playbook directory ships its own scoped `.claude/settings.json` that pre-approves
file writes **inside that playbook's folder only**, and the generated run line uses
`--permission-mode acceptEdits`. Briefs are draft-only by contract — the agent writes
artifacts into `out/`, never touches your originals — so you get zero permission nagging
without giving anything blanket access to your machine. If you want full autopilot anyway,
that's your call and your flag to add; the default stays scoped.

## What Latent is not

- **Not a screen recorder.** Tools like Screenpipe capture everything you see and say,
  all day, and mine the recording. Latent never records anything — it reads the *residue*
  your work already left behind (files, names, dates, git history) in one 60-second pass,
  then stops. No daemon, no corpus of your screen sitting on disk.
- **Not enterprise task mining.** Celonis/Pega watch *employees* for *management*.
  Latent is a mirror you point at yourself. Nobody else sees the report.
- **Not advice.** Advice is slop; receipts and a button are not. Latent only claims what
  it can evidence from your actual files, only estimates what it can show a formula for,
  and only suggests automations it can draft into a runnable brief on the spot.

## Privacy

100% local. No network calls, no telemetry, no accounts. The scan, the report, the briefs —
nothing leaves this machine. Delete `scan.json` and `playbooks/` and it's like it never ran.

## How the score works

`score = clamp(round(100 − 9 × hours), 4, 96)` where hours is the sum of per-finding
estimates, each capped per detector. Every detector's formula is printed in the report's
methodology footer. The hours are estimates and labeled as such — the receipts are not.
