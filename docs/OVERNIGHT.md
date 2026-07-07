# Latent Overnight — Act 2 contract

The mirror acquires; the inbox retains. Act 2 turns one-shot receipts into standing
work: you arm a playbook once, drafts land while you're away, you approve in seconds,
and the reclaimed-hours counter only goes up.

## Principles (research-derived, July 2026)
1. **No push-guessing.** ChatGPT Pulse died of notification fatigue; its replacement —
   a user-controlled scheduled-tasks page — is the validated model. Latent never
   volunteers work you didn't arm. New-habit suggestions appear in the report and the
   weekly digest only. The Inbox contains exclusively what you explicitly scheduled.
2. **Draft-only by default, autonomy earned per task.** 63% of teams report agents need
   more supervision than expected; trust dies on silent failures. Every run produces a
   draft + receipt. Approve a task unchanged 3 times → Latent offers (never assumes)
   full auto for that one task. Revocable anytime.
3. **The receipt is the notification.** An inbox item says what was produced, from what
   evidence, with a diff against the previous instance — never "I did some things."
4. **Local stays local.** The watcher runs on your machine, from your terminal, under
   your own agent login. Artifacts land in playbooks/tasks/. Nothing leaves.

## Model
- **Task** (tasks.json): armed from a finding. {id, findingId, kind, title, summary,
  evidence[], schedule {type: weekly|interval|manual, dow?, hour?, days?}, autonomy:
  draft|auto, approvals, paused, createdAt, lastRunAt, nextRunAt}
- **Inbox item** (inbox.json): one run's output. {id, taskId, title, producedAt,
  status: awaiting|approved|rejected|auto|failed, outDir, files[], receipt, reason?,
  hoursCredit}
- **Ledger** (ledger.json): the ratchet. {totalHours, events[{ts, taskTitle, hours}]}.
  Only approvals (or auto runs) credit it. It never decreases.

## API (server.js)
- GET  /api/tasks            → {tasks, watch}
- POST /api/tasks            → arm from finding {findingId, schedule}
- PATCH /api/tasks           → {taskId, action: pause|resume|delete|run-now|autonomy-auto|autonomy-draft}
- GET  /api/inbox            → items newest first
- POST /api/inbox            → {itemId, action: approve|reject}
- GET  /api/ledger           → {totalHours, events}

## Runner
`latent watch` (cli) → server with LATENT_WATCH=1: a 60s scheduler tick runs due tasks.
Each run: write BRIEF.md (+ scoped .claude/settings.json) into
playbooks/tasks/<taskId>/run-<ts>/, spawn `claude -p --permission-mode acceptEdits`
with cwd there (the user's own logged-in CLI — the watcher runs where their terminal
auth lives), 15-min cap, collect ./out + RECEIPT.md into an inbox item. Agent missing
or logged out → item status "failed" with the exact command to run manually. Failures
are loud, never silent.

## Frontend
Topbar gains the ratchet: "Latent has worked N.h h for you." Report cards gain "Arm
this" (schedule inferred from the finding's cadence, editable). New Inbox view (home
when items exist) + Tasks page (view/pause/edit/delete — the scheduled-tasks model).
Approve/reject inline; third unchanged approval surfaces the earn-auto offer.

## Deferred (explicitly)
- Repo-change triggers (fs watching) — v2.1
- Browser-history detector pack (opt-in, redacted, local SQLite read) — next detector release
- Calendar (.ics) source — after history
