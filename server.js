'use strict';
/*
 * LATENT — server.js
 * node:http server on PORT env || 8820. Serves ./public plus the 5-endpoint
 * API from SPEC.md. Pure Node stdlib. No npm dependencies.
 *
 * Module-system note (constrained): scanner.js is authored separately and may
 * land as either CJS or ESM, and a package.json {"type":"module"} may or may
 * not exist next to this file. This file therefore uses only syntax that is
 * valid in BOTH module systems: dynamic import() instead of require() or
 * top-level import, and process.argv[1] instead of __dirname/import.meta.url.
 */
(async function main() {
  const http = await import('node:http');
  const path = await import('node:path');
  const fsp = await import('node:fs/promises');

  // ---- paths & constants ---------------------------------------------------
  const BASE = path.dirname(path.resolve(process.argv[1])); // dir of server.js
  const PUBLIC_DIR = path.join(BASE, 'public');
  const SCAN_PATH = path.join(BASE, 'scan.json');
  const PLAYBOOKS_DIR = path.join(BASE, 'playbooks');
  const PORT = Number(process.env.PORT) || 8820;
  const BODY_CAP = 100 * 1024; // SPEC: request body cap 100KB

  // Finding ids are "<detector>:<8-char fnv1a hex>" and get used as a path
  // segment under playbooks/ — this pattern forbids every path character.
  const SAFE_ID = /^[A-Za-z0-9-]+:[A-Za-z0-9]+$/;

  const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.json': 'application/json; charset=utf-8',
    '.woff2': 'font/woff2',
  };

  // ---- "Your task" paragraph per automation.kind (SPEC BRIEF.md template) --
  const KIND_TASKS = {
    'recurring-draft':
      'This is a recurring series. Open the evidence directory, sort the series by date, and read the two or three newest instances to learn the naming pattern, the date convention, and which sections stay stable versus which change each time. Then produce the NEXT instance in the series as a draft in ./out/: correct next filename per the pattern, stable structure carried over, every date and sequence marker advanced, and a clearly marked TODO placeholder wherever fresh input is required.',
    'test-writer':
      'Read the repository named in the evidence and map its public surface: exported functions, entry points, and the behaviors the code clearly promises. Write a plan first at ./out/PLAN.md listing what you will test and why, then write a runnable test suite into ./out/tests/ using the language the repo already uses and its stdlib test tooling (no new dependencies). Cover happy paths, the obvious edge cases, and one regression-style test for each bug-prone spot you notice. End the receipt with the exact one-line command that runs the suite.',
    'doc-writer':
      'Read the repository named in the evidence — entry points, scripts, config — and reconstruct what the project is, how to run it, and how it is laid out. Write a complete README draft to ./out/README.md: a one-paragraph purpose statement, a quick start with exact commands, a file/module map, and any configuration or environment notes you can verify from the code itself. State only what the code demonstrates; mark anything inferred as an assumption.',
    'file-organizer':
      'Inventory the loose files in the evidence directory and design a small, predictable folder scheme for them — by type and date, at most two levels deep. Do not move anything. Write ./out/PLAN.md describing the scheme and why, then ./out/moves.sh: a reviewable shell script of mv commands (one per line, all paths quoted) that would carry the plan out, plus ./out/undo.sh that reverses every move.',
    'template-extractor':
      'Compare the near-identical documents in the evidence and separate the invariant skeleton from the parts that vary per instance. Write ./out/TEMPLATE.md containing the shared structure with {{placeholder}} markers at each varying field, and ./out/FIELDS.md listing every placeholder with its meaning and one real example value drawn from the evidence files.',
    'changelog-agent':
      'Read the recent git history of the repository named in the evidence (git log, read-only) and reconstruct what actually changed, grouping runs of tiny fix/wip/update commits into coherent units of work. Write ./out/CHANGELOG.md summarizing the real changes in human terms, and ./out/COMMIT_GUIDE.md: a short message convention this repo could adopt, with five example messages rewritten from its own history so future commits describe intent instead of "fix".',
    'report-assembler':
      'Read the CSV series in the evidence, confirm the shared header row, and load the most recent files. Produce ./out/report.md — the assembled report this series implies: period totals, deltas versus the previous period, notable outliers, and a compact summary table. Also write ./out/assemble.js, a Node stdlib-only script that regenerates the same report whenever a new CSV lands in that directory.',
    'scaffold-skill':
      'Diff the sibling project directories in the evidence and extract the boilerplate fileset they share. Create ./out/scaffold/ holding a canonical starter copy of each shared file with project-specific values replaced by {{name}}-style placeholders, plus ./out/new-project.sh that stamps a fresh project directory out of the scaffold given a project name.',
  };
  const FALLBACK_TASK =
    'Study the evidence above and draft the automation that would remove this recurring manual step. Write a short plan and every proposed artifact to ./out/.';

  // ---- small helpers -------------------------------------------------------
  function sendJSON(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
  }

  function httpError(status, message) {
    const err = new Error(message);
    err.status = status;
    return err;
  }

  // Read the full request body, rejecting with 413 past BODY_CAP (SPEC).
  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      let settled = false;
      req.on('data', (chunk) => {
        if (settled) return;
        size += chunk.length;
        if (size > BODY_CAP) {
          settled = true;
          // Pause (do not destroy) so the 413 response can reach the client;
          // the handler answers with Connection: close to drop the socket.
          req.pause();
          reject(httpError(413, 'body too large (100KB cap)'));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (!settled) { settled = true; resolve(Buffer.concat(chunks).toString('utf8')); }
      });
      req.on('error', (err) => {
        if (!settled) { settled = true; reject(err); }
      });
    });
  }

  // scan.json is read back by GET /api/scan and the frontend: write via
  // temp-file + rename so a concurrent read never sees a half-written file.
  // The counter makes the temp path unique even for same-millisecond writes —
  // Date.now() alone let two concurrent writes share (and corrupt) one temp file.
  let tmpSeq = 0;
  async function writeFileAtomic(file, data) {
    const tmp = `${file}.tmp-${process.pid}-${++tmpSeq}`;
    await fsp.writeFile(tmp, data);
    await fsp.rename(tmp, file);
  }

  // All scan.json read-modify-write cycles go through this chain so an
  // automate never interleaves with a rescan's final write (lost updates).
  let scanJsonLock = Promise.resolve();
  function withScanJsonLock(fn) {
    const run = scanJsonLock.then(fn, fn);
    scanJsonLock = run.then(() => undefined, () => undefined);
    return run;
  }

  // ---- scan orchestration (single-flight) ----------------------------------
  let running = false;
  let progress = null; // latest onProgress payload from the scanner
  let scannerPromise = null;

  // Lazy-load scanner.js: it is being written concurrently, so the server must
  // boot (and serve static + cached scan) even while it does not exist yet.
  function loadScanner() {
    if (!scannerPromise) {
      scannerPromise = import('./scanner.js')
        .then((mod) => {
          const runScan = mod.runScan || (mod.default && mod.default.runScan);
          if (typeof runScan !== 'function') {
            throw new Error('scanner.js does not export runScan');
          }
          return runScan;
        })
        .catch((err) => {
          scannerPromise = null; // allow retry once the file lands
          throw err;
        });
    }
    return scannerPromise;
  }

  async function startScan(roots) {
    try {
      const runScan = await loadScanner();
      const opts = roots ? { roots } : {};
      const scan = await runScan(opts, (p) => { progress = p; });
      await withScanJsonLock(async () => {
        // Finding ids hash their evidence paths, so an unchanged finding keeps
        // its id across rescans — carry its briefed status forward instead of
        // silently reverting it (and orphaning the playbook on disk).
        try {
          const prev = JSON.parse(await fsp.readFile(SCAN_PATH, 'utf8'));
          const kept = new Map((prev.findings || [])
            .filter((f) => f.automation && f.automation.status && f.automation.status !== 'idle')
            .map((f) => [f.id, f.automation]));
          for (const f of scan.findings) {
            if (kept.has(f.id)) f.automation = kept.get(f.id);
          }
        } catch (e) { /* no previous scan or unreadable — nothing to carry */ }
        await writeFileAtomic(SCAN_PATH, JSON.stringify(scan, null, 2));
      });
      progress = Object.assign({}, progress, { phase: 'done' });
    } catch (err) {
      console.error(`scan failed: ${err && err.stack ? err.stack : err}`);
      progress = { phase: 'error', error: String((err && err.message) || err) };
    } finally {
      running = false;
    }
  }

  // ---- BRIEF.md rendering (SPEC template) -----------------------------------
  function renderBrief(finding, scan, playbookDir) {
    const evidence = (finding.evidence || [])
      .map((e) => `- ${e.path} — ${e.detail}`)
      .join('\n') || '- (no evidence rows)';
    const kind = finding.automation && finding.automation.kind;
    const task = KIND_TASKS[kind] || FALLBACK_TASK;
    return `# Automation brief — ${finding.title}
Generated by Latent ${scan.generatedAt}. Status: DRAFT-ONLY. Never send/submit/push; write artifacts to ./out/.

## What keeps happening
${finding.summary}

## Evidence
${evidence}

## Your task
${task}

## Constraints
- Draft only. All output inside ${playbookDir}/out/. Do not modify the evidence files.
- Leave a RECEIPT.md: what you read, what you produced.

Run it: \`cd ${playbookDir} && claude -p --permission-mode acceptEdits "$(cat BRIEF.md)"\`
`;
  }

  // Each playbook dir ships its own scoped .claude/settings.json so the agent
  // can write drafts into out/ without a permission prompt per file. The scope
  // is the playbook dir itself — briefs are draft-only by contract, so this
  // never widens access to the rest of the machine.
  async function writePlaybookSettings(playbookDir) {
    const dir = path.join(playbookDir, '.claude');
    await fsp.mkdir(dir, { recursive: true });
    const settings = {
      permissions: {
        allow: ['Write', 'Edit', 'Read', 'Glob', 'Grep', 'Bash(node --test:*)', 'Bash(node:*)', 'Bash(mkdir:*)', 'Bash(ls:*)'],
        defaultMode: 'acceptEdits',
      },
    };
    await fsp.writeFile(path.join(dir, 'settings.json'), JSON.stringify(settings, null, 2));
  }

  // ---- API handlers ----------------------------------------------------------
  async function apiGetScan(req, res) {
    let data;
    try {
      data = await fsp.readFile(SCAN_PATH);
    } catch (err) {
      if (err.code === 'ENOENT') return sendJSON(res, 404, { error: 'no scan yet' });
      throw err;
    }
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': data.length,
    });
    res.end(data);
  }

  async function apiPostScan(req, res) {
    const raw = await readBody(req);
    let roots;
    if (raw.trim()) {
      let parsed;
      try { parsed = JSON.parse(raw); } catch (_e) {
        return sendJSON(res, 400, { error: 'invalid JSON body' });
      }
      if (parsed && Array.isArray(parsed.roots)) {
        const cleaned = parsed.roots.filter((r) => typeof r === 'string' && r.trim());
        if (cleaned.length) roots = cleaned;
      }
    }
    // Single-flight: check-and-set in one synchronous step (no await between).
    if (running) return sendJSON(res, 409, { error: 'scan already running' });
    running = true;
    progress = { phase: 'walking', filesSeen: 0, dirsSeen: 0, currentPath: '' };
    startScan(roots); // fire and forget; resets `running` in its finally
    sendJSON(res, 202, { started: true });
  }

  function apiGetProgress(req, res) {
    // SPEC: "latest progress object + {running:bool}". Fields are merged into
    // the response; a nested `progress` copy is also included so either read
    // style works for the frontend.
    const p = progress || {};
    sendJSON(res, 200, Object.assign({}, p, { running, progress: p }));
  }

  async function apiPostAutomate(req, res) {
    const raw = await readBody(req);
    let body;
    try { body = raw.trim() ? JSON.parse(raw) : {}; } catch (_e) {
      return sendJSON(res, 400, { error: 'invalid JSON body' });
    }
    const findingId = body && body.findingId;
    if (typeof findingId !== 'string' || !findingId) {
      return sendJSON(res, 400, { error: 'findingId required' });
    }

    const result = await withScanJsonLock(async () => {
      let scan;
      try {
        scan = JSON.parse(await fsp.readFile(SCAN_PATH, 'utf8'));
      } catch (err) {
        if (err.code === 'ENOENT') return { status: 404, body: { error: 'no scan yet' } };
        return { status: 500, body: { error: 'scan.json is unreadable' } };
      }

      const finding = (scan.findings || []).find((f) => f.id === findingId);
      if (!finding) return { status: 404, body: { error: 'unknown finding id' } };
      // finding.id becomes a directory name — refuse anything path-shaped.
      if (!SAFE_ID.test(finding.id)) {
        return { status: 400, body: { error: 'finding id contains unsafe characters' } };
      }

      const playbookDir = path.join(PLAYBOOKS_DIR, finding.id);
      await fsp.mkdir(playbookDir, { recursive: true });
      const brief = renderBrief(finding, scan, playbookDir);
      const briefPath = path.join(playbookDir, 'BRIEF.md');
      await fsp.writeFile(briefPath, brief);
      await writePlaybookSettings(playbookDir);

      finding.automation = finding.automation || {};
      finding.automation.status = 'briefed';
      finding.automation.briefPath = briefPath;
      await writeFileAtomic(SCAN_PATH, JSON.stringify(scan, null, 2));
      return { status: 200, body: { brief, briefPath } };
    });
    sendJSON(res, result.status, result.body);
  }

  async function apiGetBrief(req, res, u) {
    const id = u.searchParams.get('id');
    if (!id) return sendJSON(res, 400, { error: 'id required' });
    if (!SAFE_ID.test(id)) return sendJSON(res, 400, { error: 'invalid id' });
    let brief;
    try {
      brief = await fsp.readFile(path.join(PLAYBOOKS_DIR, id, 'BRIEF.md'), 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return sendJSON(res, 404, { error: 'no brief for this finding' });
      throw err;
    }
    sendJSON(res, 200, { brief });
  }

  // ---- static files -----------------------------------------------------------
  async function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return sendJSON(res, 405, { error: 'method not allowed' });
    }
    let decoded;
    try { decoded = decodeURIComponent(pathname); } catch (_e) {
      return sendJSON(res, 400, { error: 'bad path' });
    }
    if (decoded.includes('\0')) return sendJSON(res, 400, { error: 'bad path' });

    const rel = decoded.replace(/^\/+/, '') || 'index.html';
    let abs = path.normalize(path.join(PUBLIC_DIR, rel));
    // Traversal guard: resolved path must stay inside public/.
    if (abs !== PUBLIC_DIR && !abs.startsWith(PUBLIC_DIR + path.sep)) {
      return sendJSON(res, 403, { error: 'forbidden' });
    }

    try {
      const st = await fsp.stat(abs);
      if (st.isDirectory()) abs = path.join(abs, 'index.html');
    } catch (_e) {
      // fall through to the read attempt below (handles index fallback there)
    }

    let data;
    try {
      data = await fsp.readFile(abs);
    } catch (err) {
      if (err.code !== 'ENOENT' && err.code !== 'EISDIR') throw err;
      // Index fallback: extensionless paths get the SPA shell; assets 404.
      if (!path.extname(rel)) {
        try {
          data = await fsp.readFile(path.join(PUBLIC_DIR, 'index.html'));
          abs = path.join(PUBLIC_DIR, 'index.html');
        } catch (_e2) {
          return sendJSON(res, 404, { error: 'not found' });
        }
      } else {
        return sendJSON(res, 404, { error: 'not found' });
      }
    }

    res.writeHead(200, {
      'Content-Type': MIME[path.extname(abs).toLowerCase()] || 'application/octet-stream',
      'Content-Length': data.length,
    });
    res.end(req.method === 'HEAD' ? undefined : data);
  }

  // ---- router -------------------------------------------------------------------
  async function handle(req, res) {
    const u = new URL(req.url, 'http://localhost');
    const p = u.pathname;

    if (p === '/api/scan') {
      if (req.method === 'GET') return apiGetScan(req, res);
      if (req.method === 'POST') return apiPostScan(req, res);
      return sendJSON(res, 405, { error: 'method not allowed' });
    }
    if (p === '/api/progress') {
      if (req.method === 'GET') return apiGetProgress(req, res);
      return sendJSON(res, 405, { error: 'method not allowed' });
    }
    if (p === '/api/automate') {
      if (req.method === 'POST') return apiPostAutomate(req, res);
      return sendJSON(res, 405, { error: 'method not allowed' });
    }
    if (p === '/api/brief') {
      if (req.method === 'GET') return apiGetBrief(req, res, u);
      return sendJSON(res, 405, { error: 'method not allowed' });
    }
    if (p.startsWith('/api/')) return sendJSON(res, 404, { error: 'not found' });

    return serveStatic(req, res, p);
  }

  // ---- server -----------------------------------------------------------------
  const server = http.createServer((req, res) => {
    const started = Date.now();
    // One log line per request (SPEC), emitted when the response closes.
    res.once('close', () => {
      console.log(
        `${new Date().toISOString()} ${req.method} ${req.url} ${res.statusCode} ${Date.now() - started}ms`
      );
    });
    handle(req, res).catch((err) => {
      const status = err && err.status ? err.status : 500;
      const message = status === 500 ? 'internal error' : String(err.message);
      if (status === 500) console.error(err && err.stack ? err.stack : err);
      if (!res.headersSent) {
        if (status === 413) res.setHeader('Connection', 'close');
        sendJSON(res, status, { error: message });
      } else {
        res.end();
      }
    });
  });

  server.on('error', (err) => {
    console.error(`server error: ${err && err.message ? err.message : err}`);
    process.exit(1);
  });

  server.listen(PORT, () => {
    console.log(`latent listening on http://localhost:${PORT} (public: ${PUBLIC_DIR})`);
  });
})();
