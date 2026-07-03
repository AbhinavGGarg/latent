#!/usr/bin/env node
'use strict';
/*
 * LATENT — scanner.js
 * CLI + module. Pure Node stdlib, no external deps.
 *
 *   node scanner.js [--roots=a,b] [--out=scan.json]
 *   const { runScan, DETECTORS, ESTIMATES } = require('./scanner');
 *
 * Walks the given roots once, builds a file index, runs 10 detectors over it,
 * and emits the scan object defined in SPEC.md. Every fs touch is wrapped;
 * EPERM/EACCES/ENOENT (and anything else) count into stats.skipped, never throw.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');

// ---------------------------------------------------------------------------
// Constants (walker contract)
// ---------------------------------------------------------------------------

const MAX_FILES = 60000;          // hard cap on indexed files
const MAX_DEPTH = 7;              // dirs deeper than this below a root are not read
const TEXT_READ_MAX = 200 * 1024; // per-file text reads only up to 200KB
const TEXT_READ_EXTS = new Set(['.md', '.txt', '.csv', '.json']); // read whitelist

// Excluded directory names (.git contents are skipped but the repo is noted).
const EXCLUDE_DIRS = new Set([
  'node_modules', '.git', 'Library', '.cache', '.npm', '.Trash',
  'venv', '.venv', 'env', '.tox', 'site-packages', 'Pods', 'vendor',
  '__pycache__', 'dist', 'build', '.next', 'chrome_data', 'User Data',
]);

// Machine noise is never evidence of human work: caches (GPUCache,
// DawnWebGPUCache, ...) and macOS .app bundle internals stay out of the index.
// Exact names only — a project named "apicache" or "CacheKit" is real work.
const CACHE_DIR_NAMES = new Set([
  'cache', 'caches', 'cachedata', 'cachestorage', 'code cache', 'gpucache',
  'shadercache', 'grshadercache', 'dawnwebgpucache', 'dawngraphitecache',
  'graphitedawncache', 'component_crx_cache', 'cachedextensions', 'script cache',
]);

function isExcludedDir(name, fullPath) {
  if (EXCLUDE_DIRS.has(name)) return true;
  if (CACHE_DIR_NAMES.has(name.toLowerCase())) return true;
  if (name.endsWith('.app')) {
    // Real .app bundles have a Contents dir; a project folder named "my.app" doesn't.
    try { return fs.lstatSync(path.join(fullPath, 'Contents')).isDirectory(); }
    catch (e) { return false; }
  }
  return false;
}

const SOURCE_EXTS = new Set(['.js', '.ts', '.py', '.go', '.rs', '.tsx']);
const TEXT_DOC_EXTS = new Set(['.md', '.txt', '.rtf', '.tex', '.doc', '.docx', '.pages']);

// ---------------------------------------------------------------------------
// fnv1a — id hashing. MUST use >>> (unsigned): a signed >> can go negative
// past 2^31 and produce broken hex ids.
// ---------------------------------------------------------------------------

function fnv1aNum(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    // h * 16777619 (FNV prime) mod 2^32, via shifts; >>> keeps it unsigned.
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h >>> 0; // unsigned — never negative
}

function fnv1aHex(str) {
  return fnv1aNum(str).toString(16).padStart(8, '0').slice(0, 8);
}

// ---------------------------------------------------------------------------
// ESTIMATES — per-detector formula + cap, as data. `hours(m)` computes the raw
// hours/week from detector metrics; `capHoursPerWeek` bounds it; `formula` is
// the human-readable string surfaced in the methodology footer.
// ---------------------------------------------------------------------------

const ESTIMATES = {
  'version-chains': {
    capHoursPerWeek: 1.5,
    formula: '(versions - 1) x 4 min, spread over the chain mtime span in weeks (min 1 wk); cap 1.5 h/wk',
    hours: (m) => ((m.count - 1) * 4 / 60) / Math.max(m.spanWeeks, 1),
  },
  'dated-recurrence': {
    capHoursPerWeek: 3.0,
    formula: 'instances per week x 45 min (text docs) or 25 min (other files); cap 3.0 h/wk',
    hours: (m) => m.perWeek * (m.isText ? 45 : 25) / 60,
  },
  'near-duplicate-text': {
    capHoursPerWeek: 2.0,
    formula: '(cluster size - 1) x 12 min, spread over the cluster mtime span in weeks (min 1 wk); cap 2.0 h/wk',
    hours: (m) => ((m.count - 1) * 12 / 60) / Math.max(m.spanWeeks, 1),
  },
  'untested-repos': {
    capHoursPerWeek: 1.5,
    formula: 'one-shot 2.5 h per repo, amortized over 8 wk; cap 1.5 h/wk',
    hours: (m) => m.repoCount * 2.5 / 8,
  },
  'undocumented-repos': {
    capHoursPerWeek: 0.5,
    formula: 'one-shot 40 min per repo, amortized over 8 wk; cap 0.5 h/wk',
    hours: (m) => m.repoCount * (40 / 60) / 8,
  },
  'screenshot-pileup': {
    capHoursPerWeek: 0.3,
    formula: 'count x 20 s, spread over the pileup mtime span in weeks (min 1 wk); cap 0.3 h/wk',
    hours: (m) => (m.count * 20 / 3600) / Math.max(m.spanWeeks, 1),
  },
  'downloads-entropy': {
    capHoursPerWeek: 0.8,
    formula: '15 min/wk + 5 min per 100 loose files; cap 0.8 h/wk',
    hours: (m) => (15 + 5 * (m.count / 100)) / 60,
  },
  'commit-drudgery': {
    capHoursPerWeek: 0.5,
    formula: 'generic-message rate x commits per week x 2 min; cap 0.5 h/wk',
    hours: (m) => m.rate * m.commitsPerWeek * 2 / 60,
  },
  'csv-report-assembly': {
    capHoursPerWeek: 2.0,
    formula: 'instances per week x 25 min; cap 2.0 h/wk',
    hours: (m) => m.perWeek * 25 / 60,
  },
  'scaffold-repetition': {
    capHoursPerWeek: 0.7,
    formula: 'one-shot 35 min per project dir, amortized over 8 wk; cap 0.7 h/wk',
    hours: (m) => m.dirCount * (35 / 60) / 8,
  },
};

function round2(x) { return Math.round(x * 100) / 100; }

// Apply the detector's formula, then its cap. Floor at 0.01 so a real finding
// never rounds to zero hours.
function estimateHours(detector, metricsInput) {
  const e = ESTIMATES[detector];
  const raw = e.hours(metricsInput);
  return Math.max(round2(Math.min(raw, e.capHoursPerWeek)), 0.01);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const WEEK_MS = 7 * 24 * 3600 * 1000;

function spanWeeksOf(files) {
  if (!files.length) return 0;
  let min = Infinity, max = -Infinity;
  for (const f of files) { if (f.mtime < min) min = f.mtime; if (f.mtime > max) max = f.mtime; }
  return (max - min) / WEEK_MS;
}

function iso(ms) { return new Date(ms).toISOString(); }

function tilde(p, home) {
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

function newestFirst(files) { return files.slice().sort((a, b) => b.mtime - a.mtime); }
function oldestFirst(files) { return files.slice().sort((a, b) => a.mtime - b.mtime); }

// id = <detector>:<8-char fnv1a hex of joined evidence paths>
function makeFinding(detector, title, summary, evidence, metrics) {
  const meta = DETECTOR_META[detector];
  return {
    id: detector + ':' + fnv1aHex(evidence.map((e) => e.path).join('|')),
    detector,
    title,
    summary,
    evidence,
    metrics,
    automation: { kind: meta.kind, title: meta.title, status: 'idle', briefPath: null },
  };
}

// ---------------------------------------------------------------------------
// Walker — one pass, builds the file index. No symlink following: dirents are
// lstat-semantics (readdir never resolves links), and anything reporting
// isSymbolicLink() is dropped on the floor.
// ---------------------------------------------------------------------------

// Generic defaults: the big three user dirs plus whichever common code
// folders exist on this machine. resolveRoots drops the ones that don't.
function defaultRoots(home) {
  return [
    path.join(home, 'Downloads'),
    path.join(home, 'Desktop'),
    path.join(home, 'Documents'),
    path.join(home, 'Projects'),
    path.join(home, 'projects'),
    path.join(home, 'Developer'),
    path.join(home, 'dev'),
    path.join(home, 'code'),
    path.join(home, 'repos'),
    path.join(home, 'workspace'),
  ];
}

function resolveRoots(requested, home) {
  const list = (requested && requested.length ? requested : defaultRoots(home))
    .map((r) => path.resolve(String(r)));
  const existing = [];
  for (const r of list) {
    try {
      if (fs.lstatSync(r).isDirectory() && !existing.includes(r)) existing.push(r);
    } catch (e) { /* missing default root: silently dropped, per "existing only" */ }
  }
  // Drop roots nested inside another root so files are never indexed twice.
  existing.sort((a, b) => a.length - b.length);
  const roots = [];
  for (const r of existing) {
    if (!roots.some((kept) => r === kept || r.startsWith(kept + path.sep))) roots.push(r);
  }
  return roots;
}

function walk(roots, stats, emit) {
  const files = [];
  const repos = new Set();
  const stack = roots.map((r) => ({ dir: r, depth: 0, root: r }));

  while (stack.length) {
    const { dir, depth, root } = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      stats.skipped++; // EPERM/EACCES/ENOENT and friends — count, never throw
      continue;
    }
    stats.dirs++;

    // A dir containing `.git` (dir or file) is a repo; contents of .git are
    // still excluded from the walk below.
    if (entries.some((ent) => ent.name === '.git')) {
      if (!repos.has(dir)) { repos.add(dir); stats.repos++; }
    }

    for (const ent of entries) {
      if (files.length >= MAX_FILES) return { files, repos };
      const name = ent.name;
      const p = path.join(dir, name);
      if (ent.isSymbolicLink()) continue; // never follow symlinks
      if (ent.isDirectory()) {
        if (isExcludedDir(name, p)) continue;
        if (depth + 1 <= MAX_DEPTH) stack.push({ dir: p, depth: depth + 1, root });
      } else if (ent.isFile()) {
        let st;
        try {
          st = fs.lstatSync(p); // lstat: a race-created symlink is still not followed
        } catch (e) { stats.skipped++; continue; }
        if (!st.isFile()) continue;
        files.push({
          path: p, dir, base: name,
          ext: path.extname(name).toLowerCase(),
          size: st.size, mtime: st.mtimeMs, root,
        });
        stats.files++;
        emit('walking', p);
      }
      // Sockets/FIFOs/unknown dirent types are ignored.
    }
  }
  return { files, repos };
}

// ---------------------------------------------------------------------------
// Context shared by detectors
// ---------------------------------------------------------------------------

function buildContext(files, repos, roots, stats, home) {
  const byDir = new Map();
  for (const f of files) {
    let arr = byDir.get(f.dir);
    if (!arr) { arr = []; byDir.set(f.dir, arr); }
    arr.push(f);
  }

  // Assign each file to its deepest containing repo (nested repos own their files).
  const repoList = [...repos].sort((a, b) => b.length - a.length);
  const repoFiles = new Map(repoList.map((r) => [r, []]));
  if (repoList.length) {
    for (const f of files) {
      for (const r of repoList) {
        if (f.path.startsWith(r + path.sep)) { repoFiles.get(r).push(f); break; }
      }
    }
  }

  const textCache = new Map();
  function readText(f) {
    // Per-file text reads only for whitelisted exts, <= 200KB.
    if (!TEXT_READ_EXTS.has(f.ext) || f.size > TEXT_READ_MAX || f.size === 0) return null;
    if (textCache.has(f.path)) return textCache.get(f.path);
    let text = null;
    try {
      text = fs.readFileSync(f.path, 'utf8');
      stats.textFilesSampled++;
    } catch (e) {
      stats.skipped++; // unreadable text file — skip, never throw
    }
    textCache.set(f.path, text);
    return text;
  }

  // git log via execFile with a hard 3s timeout; ANY error (no git, not a real
  // repo, timeout kill) resolves to null and the repo is silently skipped.
  function gitLog(repoDir) {
    return new Promise((resolve) => {
      let settled = false;
      const done = (v) => { if (!settled) { settled = true; resolve(v); } };
      try {
        execFile(
          'git', ['log', '--pretty=%ct%x09%s', '-n', '300'],
          { cwd: repoDir, timeout: 3000, maxBuffer: 1024 * 1024, windowsHide: true },
          (err, stdout) => {
            if (err) return done(null);
            const out = [];
            for (const line of String(stdout).split('\n')) {
              const tab = line.indexOf('\t');
              if (tab < 1) continue;
              const ts = Number(line.slice(0, tab));
              if (!Number.isFinite(ts)) continue;
              out.push({ ts: ts * 1000, subject: line.slice(tab + 1) });
            }
            done(out.length ? out : null);
          }
        );
      } catch (e) { done(null); }
    });
  }

  return {
    files, byDir, repos: repoList, repoFiles, roots, stats, home,
    claimed: new Set(), // paths already explained by a detector — prevents double-counted hours
    readText, gitLog,
  };
}

function isUnderAnyRepo(dir, repoList) {
  return repoList.some((r) => dir === r || dir.startsWith(r + path.sep));
}

// ---------------------------------------------------------------------------
// Date parsing shared by dated-recurrence (and used to keep version-chains
// from re-claiming dated series). \b is useless next to `_`, so patterns
// anchor on non-digit neighbors instead.
// ---------------------------------------------------------------------------

const DATE_PATTERNS = [
  // YYYY-MM-DD / YYYY_MM_DD / YYYY.MM.DD / YYYYMMDD (same separator both sides)
  { kind: 'ymd', re: /(^|\D)(20\d{2})([-_.]?)(0[1-9]|1[0-2])\3(0[1-9]|[12]\d|3[01])(?!\d)/ },
  // DD-MM-YYYY or MM-DD-YYYY (disambiguated by value)
  { kind: 'xxy', re: /(^|\D)(\d{1,2})([-_.])(\d{1,2})\3(20\d{2})(?!\d)/ },
  // MM-DD (zero-padded), year inferred from the file mtime
  { kind: 'md', re: /(^|\D)(0[1-9]|1[0-2])([-_.])(0[1-9]|[12]\d|3[01])(?!\d)/ },
];

function findDateInName(base, mtimeMs) {
  for (const { kind, re } of DATE_PATTERNS) {
    const m = re.exec(base);
    if (!m) continue;
    let y, mo, d;
    if (kind === 'ymd') {
      y = +m[2]; mo = +m[4]; d = +m[5];
    } else if (kind === 'xxy') {
      const a = +m[2], b = +m[4]; y = +m[5];
      if (a > 12 && b >= 1 && b <= 12) { d = a; mo = b; }
      else if (a >= 1 && a <= 12 && b >= 1 && b <= 31) { mo = a; d = b; }
      else continue;
    } else { // md — borrow the year from mtime, roll back if it lands in the future
      mo = +m[2]; d = +m[4];
      y = new Date(mtimeMs).getFullYear();
      if (Date.UTC(y, mo - 1, d) > mtimeMs + 60 * 24 * 3600 * 1000) y -= 1;
    }
    const t = Date.UTC(y, mo - 1, d);
    const dt = new Date(t);
    if (dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) continue; // e.g. 02-31
    const start = m.index + m[1].length;
    const len = m[0].length - m[1].length;
    return { t, template: base.slice(0, start) + '{date}' + base.slice(start + len) };
  }
  return null;
}

function periodStats(timesMs) {
  // distinct days, sorted; positive gaps only
  const days = [...new Set(timesMs.map((t) => Math.floor(t / 86400000)))].sort((a, b) => a - b);
  if (days.length < 4) return null;
  const gaps = [];
  for (let i = 1; i < days.length; i++) gaps.push(days[i] - days[i - 1]);
  const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length;
  if (mean <= 0) return null;
  const variance = gaps.reduce((s, g) => s + (g - mean) * (g - mean), 0) / gaps.length;
  const cv = Math.sqrt(variance) / mean;
  return { meanGapDays: mean, cv, distinct: days.length };
}

// ---------------------------------------------------------------------------
// Detector 1 — version-chains
// ---------------------------------------------------------------------------

function stripVersionTokens(nameNoExt) {
  let s = nameNoExt.toLowerCase();
  s = s.replace(/\(\d+\)/g, ' ');                                        // "(1)" copies
  s = s.replace(/(^|\D)20\d{2}[-_.]?\d{2}[-_.]?\d{2}(?!\d)/g, '$1 ');    // YYYY-MM-DD / YYYYMMDD
  s = s.replace(/(^|\D)\d{1,2}[-_.]\d{1,2}[-_.]20\d{2}(?!\d)/g, '$1 '); // DD-MM-YYYY
  s = s.replace(/[-_. ]+/g, ' ');                                        // normalize separators
  s = s.replace(/\bv(?:er|ersion)?\s?\d+\b/g, ' ');                      // v2 / ver 3 / version4
  s = s.replace(/\b(final|copy|draft|old|new)\b/g, ' ');                 // version words
  s = s.replace(/\s+/g, ' ').trim();
  s = s.replace(/\s*\d+$/, '').trim();                                   // trailing digits
  return s;
}

// Camera/phone exports carry serial numbers (IMG_5714.HEIC, DSC0042, PXL_...)
// that look like version chains but are not human re-saving. Same for media
// files generally and extensionless cache blobs (data_1, data_2, ...).
const MEDIA_EXTS = new Set([
  '.heic', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.mov', '.mp4', '.m4v',
  '.avi', '.mkv', '.dng', '.tiff', '.bmp', '.aae', '.aac', '.mp3', '.wav',
]);
const CAMERA_RE = /^(img|dsc|dscf|pxl|mvi|gopr|gx\d|whatsapp image|signal-|photo|facetime)[-_ ]?\d/i;

function detectVersionChains(ctx) {
  const groups = new Map();
  const bases = new Map(); // token-less originals: "report.md" belongs to the "report v2.md" chain
  for (const f of ctx.files) {
    if (ctx.claimed.has(f.path)) continue; // already explained as a dated/csv series
    if (f.ext === '' || MEDIA_EXTS.has(f.ext)) continue;
    if (CAMERA_RE.test(f.base) || SCREENSHOT_RE.test(f.base)) continue;
    const nameNoExt = f.base.slice(0, f.base.length - f.ext.length);
    const key = stripVersionTokens(nameNoExt);
    if (key.length < 2 || !/[a-z]/.test(key)) continue;
    // Compare against the separator-normalized name, not the raw one:
    // "meeting-notes" → "meeting notes" is normalization, not a version token.
    // Only a genuinely stripped token makes a file a version variant.
    const norm = nameNoExt.toLowerCase().replace(/[-_. ]+/g, ' ').trim();
    const gk = f.dir + ' ' + key + ' ' + f.ext;
    if (key === norm) { bases.set(gk, f); continue; } // no token: chain-base candidate
    let g = groups.get(gk);
    if (!g) { g = { key, files: [] }; groups.set(gk, g); }
    g.files.push(f);
  }

  const findings = [];
  for (const [gk, g] of groups) {
    const base = bases.get(gk);
    if (base && !ctx.claimed.has(base.path)) g.files.push(base); // "report.md" joins {report v1.md, report v2.md}
    if (g.files.length < 3) continue;
    const chain = oldestFirst(g.files);
    for (const f of chain) ctx.claimed.add(f.path);
    const n = chain.length;
    const spanWeeks = spanWeeksOf(chain);
    const first = chain[0], last = chain[n - 1];
    const evidence = [{
      path: last.path,
      detail: `${n} versions, ${first.base} → ${last.base}`,
      mtime: iso(last.mtime),
    }];
    for (const f of chain.slice(0, 5)) {
      if (f.path === last.path && evidence.length > 1) continue;
      evidence.push({ path: f.path, detail: `version ${chain.indexOf(f) + 1} of ${n}`, mtime: iso(f.mtime) });
    }
    const est = estimateHours('version-chains', { count: n, spanWeeks });
    const weeks = Math.max(1, Math.round(spanWeeks));
    findings.push(makeFinding(
      'version-chains',
      'You version files by hand',
      `You kept ${n} hand-made copies of "${g.key}${last.ext}" in ${tilde(last.dir, ctx.home)}, ` +
      `saved one at a time over ${weeks} week${weeks === 1 ? '' : 's'}.`,
      evidence,
      { count: n, estMinutesPerInstance: 4, estHoursPerWeek: est, confidence: 0.85, oneShot: false }
    ));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 2 — dated-recurrence (THE flagship)
// ---------------------------------------------------------------------------

function detectDatedRecurrence(ctx) {
  const groups = new Map();
  for (const f of ctx.files) {
    const hit = findDateInName(f.base, f.mtime);
    if (!hit) continue;
    const gk = f.dir + ' ' + hit.template;
    let g = groups.get(gk);
    if (!g) { g = { template: hit.template, dir: f.dir, files: [], times: [] }; groups.set(gk, g); }
    g.files.push(f);
    g.times.push(hit.t);
  }

  const findings = [];
  for (const g of groups.values()) {
    if (g.files.length < 4) continue;
    const p = periodStats(g.times);
    if (!p || p.cv >= 0.6) continue; // must be near-regular
    for (const f of g.files) ctx.claimed.add(f.path);

    const n = g.files.length;
    const perWeek = 7 / p.meanGapDays;
    const ext = g.files[0].ext;
    const isText = TEXT_DOC_EXTS.has(ext);
    const est = estimateHours('dated-recurrence', { perWeek, isText });
    const chain = newestFirst(g.files);
    const every = Math.round(p.meanGapDays);

    const evidence = [{
      path: chain[0].path,
      detail: `${n} dated files, one every ~${every} day${every === 1 ? '' : 's'}`,
      mtime: iso(chain[0].mtime),
    }];
    for (const f of chain.slice(1, 6)) {
      evidence.push({ path: f.path, detail: 'earlier instance', mtime: iso(f.mtime) });
    }
    findings.push(makeFinding(
      'dated-recurrence',
      'You produce the same file on a schedule',
      `You have written ${n} dated instances of "${g.template}" in ${tilde(g.dir, ctx.home)}, ` +
      `one every ~${every} day${every === 1 ? '' : 's'}. Each new one starts from the last, by hand.`,
      evidence,
      { count: n, estMinutesPerInstance: isText ? 45 : 25, estHoursPerWeek: est, confidence: 0.9, oneShot: false }
    ));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 3 — near-duplicate-text
// ---------------------------------------------------------------------------

function shingleSet(text) {
  const words = text.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (words.length < 40) return null;
  const cap = Math.min(words.length, 20000); // bound work on big files
  const set = new Set();
  for (let i = 0; i + 5 <= cap; i++) {
    set.add(fnv1aNum(
      words[i] + ' ' + words[i + 1] + ' ' + words[i + 2] + ' ' + words[i + 3] + ' ' + words[i + 4]
    ));
  }
  return set.size ? set : null;
}

function jaccard(a, b) {
  const [small, big] = a.size <= b.size ? [a, b] : [b, a];
  let inter = 0;
  for (const v of small) if (big.has(v)) inter++;
  return inter / (a.size + b.size - inter);
}

function detectNearDuplicateText(ctx) {
  // Candidates: .md/.txt, 0.5–200KB, not already explained by another detector.
  // Legal/boilerplate files are identical by design, not re-typed by anyone.
  const BOILERPLATE_RE = /^(license|licence|copying|notice|changelog|contributing|code_of_conduct|third[-_ ]?party)/i;
  const byRoot = new Map();
  for (const f of ctx.files) {
    if (ctx.claimed.has(f.path)) continue;
    if (f.ext !== '.md' && f.ext !== '.txt') continue;
    if (BOILERPLATE_RE.test(f.base)) continue;
    if (f.size < 512 || f.size > TEXT_READ_MAX) continue;
    let arr = byRoot.get(f.root);
    if (!arr) { arr = []; byRoot.set(f.root, arr); }
    arr.push(f);
  }

  const findings = [];
  for (const candidates of byRoot.values()) {
    // Bound the O(n^2) comparison per root.
    const picked = newestFirst(candidates).slice(0, 250);
    const items = [];
    for (const f of picked) {
      const text = ctx.readText(f);
      if (!text) continue;
      const sh = shingleSet(text);
      if (sh) items.push({ f, sh });
    }
    if (items.length < 3) continue;

    // union-find over pairs with Jaccard >= 0.7 (5-word shingles)
    const parent = items.map((_, i) => i);
    const find = (x) => { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; };
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const a = items[i].sh, b = items[j].sh;
        const min = Math.min(a.size, b.size), max = Math.max(a.size, b.size);
        if (min / max < 0.65) continue; // Jaccard 0.7 needs similar set sizes
        if (jaccard(a, b) >= 0.7) { const ra = find(i), rb = find(j); if (ra !== rb) parent[ra] = rb; }
      }
    }
    const clusters = new Map();
    for (let i = 0; i < items.length; i++) {
      const r = find(i);
      let arr = clusters.get(r);
      if (!arr) { arr = []; clusters.set(r, arr); }
      arr.push(items[i].f);
    }

    for (const cluster of clusters.values()) {
      if (cluster.length < 3) continue;
      const n = cluster.length;
      const spanWeeks = spanWeeksOf(cluster);
      const est = estimateHours('near-duplicate-text', { count: n, spanWeeks });
      const sorted = newestFirst(cluster);
      const evidence = sorted.slice(0, 6).map((f, i) => ({
        path: f.path,
        detail: i === 0 ? `${n} files share ≥70% of their text` : `${(f.size / 1024).toFixed(1)} KB near-duplicate`,
        mtime: iso(f.mtime),
      }));
      for (const f of cluster) ctx.claimed.add(f.path);
      findings.push(makeFinding(
        'near-duplicate-text',
        'You rewrite nearly identical documents',
        `${n} files under ${tilde(cluster[0].root, ctx.home)} share at least 70% of their text. ` +
        `You are re-typing a template instead of generating from one.`,
        evidence,
        { count: n, estMinutesPerInstance: 12, estHoursPerWeek: est, confidence: 0.8, oneShot: false }
      ));
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detectors 4 & 5 — untested-repos / undocumented-repos (one aggregate finding
// each; the per-repo estimate sums, then the detector cap applies)
// ---------------------------------------------------------------------------

const TEST_DIR_SEGMENTS = new Set(['test', 'tests', 'spec', 'specs', '__tests__']);

function isTestFile(f, repoRoot) {
  const rel = f.path.slice(repoRoot.length + 1);
  for (const seg of rel.split(path.sep).slice(0, -1)) {
    if (TEST_DIR_SEGMENTS.has(seg.toLowerCase())) return true;
  }
  const b = f.base.toLowerCase();
  return /(^|[._-])(test|spec)s?[._-]/.test(b) || /\.(test|spec)\./.test(b)
    || /(^|[._-])(test|spec)s?\./.test(b);
}

function repoCodeStats(ctx, repo) {
  const files = ctx.repoFiles.get(repo) || [];
  let src = 0, tests = 0, newest = 0;
  for (const f of files) {
    // Only source files count as either src or tests — otherwise a SPEC.md or
    // test_data.csv silently satisfies "has tests" and suppresses the finding.
    if (!SOURCE_EXTS.has(f.ext)) continue;
    if (isTestFile(f, repo)) { tests++; continue; }
    src++; if (f.mtime > newest) newest = f.mtime;
  }
  return { src, tests, newest: newest || Date.now() };
}

function detectUntestedRepos(ctx) {
  const hits = [];
  for (const repo of ctx.repos) {
    const { src, tests, newest } = repoCodeStats(ctx, repo);
    if (src >= 8 && tests === 0) hits.push({ repo, src, newest });
  }
  if (!hits.length) return [];
  hits.sort((a, b) => b.src - a.src);
  const totalSrc = hits.reduce((s, h) => s + h.src, 0);
  const est = estimateHours('untested-repos', { repoCount: hits.length });
  const evidence = hits.slice(0, 8).map((h) => ({
    path: h.repo, detail: `${h.src} source files, 0 tests`, mtime: iso(h.newest),
  }));
  return [makeFinding(
    'untested-repos',
    'Your repos have no tests',
    `${hits.length} repo${hits.length === 1 ? '' : 's'} with ${totalSrc} source files contain zero test files. ` +
    `Every change is verified by hand, or not at all.`,
    evidence,
    { count: hits.length, estMinutesPerInstance: 150, estHoursPerWeek: est, confidence: 0.75, oneShot: true }
  )];
}

function detectUndocumentedRepos(ctx) {
  const hits = [];
  for (const repo of ctx.repos) {
    const { src, newest } = repoCodeStats(ctx, repo);
    if (src < 1) continue; // "repos with code"
    const rootFiles = ctx.byDir.get(repo) || [];
    // Judge the best readme present, not the first one readdir happens to
    // return — an 80-byte readme.txt stub must not mask a real README.md.
    const readmes = rootFiles.filter((f) => /^readme(\.|$)/i.test(f.base));
    const best = readmes.reduce((a, b) => (!a || b.size > a.size ? b : a), null);
    if (best && best.size >= 300) continue;
    hits.push({
      repo, src, newest,
      detail: best ? `README is ${best.size} bytes` : 'no README',
    });
  }
  if (!hits.length) return [];
  hits.sort((a, b) => b.src - a.src);
  const est = estimateHours('undocumented-repos', { repoCount: hits.length });
  const evidence = hits.slice(0, 8).map((h) => ({
    path: h.repo, detail: `${h.src} source files, ${h.detail}`, mtime: iso(h.newest),
  }));
  return [makeFinding(
    'undocumented-repos',
    'Your repos ship without a README',
    `${hits.length} repo${hits.length === 1 ? '' : 's'} with code have no usable README. ` +
    `Anyone opening them starts from zero, including you in six months.`,
    evidence,
    { count: hits.length, estMinutesPerInstance: 40, estHoursPerWeek: est, confidence: 0.7, oneShot: true }
  )];
}

// ---------------------------------------------------------------------------
// Detector 6 — screenshot-pileup
// ---------------------------------------------------------------------------

const SCREENSHOT_RE = /^(screen ?shot|screen recording|scr-)/i;

function screenshotLocations(ctx) {
  const locs = new Set([path.join(ctx.home, 'Desktop'), path.join(ctx.home, 'Downloads')]);
  for (const r of ctx.roots) {
    if (/^(desktop|downloads)$/i.test(path.basename(r))) locs.add(r);
  }
  return [...locs];
}

function detectScreenshotPileup(ctx) {
  const findings = [];
  for (const loc of screenshotLocations(ctx)) {
    // Top level only: screenshots the user already filed into subfolders are
    // exactly the behavior this detector rewards, not a pileup.
    const shots = ctx.files.filter((f) => f.dir === loc && SCREENSHOT_RE.test(f.base));
    if (shots.length < 15) continue;
    const n = shots.length;
    const spanWeeks = spanWeeksOf(shots);
    const est = estimateHours('screenshot-pileup', { count: n, spanWeeks });
    const sorted = newestFirst(shots);
    const oldest = sorted[n - 1];
    const evidence = [{
      path: loc, detail: `${n} screenshots and recordings, oldest ${iso(oldest.mtime).slice(0, 10)}`, mtime: iso(sorted[0].mtime),
    }];
    for (const f of sorted.slice(0, 5)) {
      evidence.push({ path: f.path, detail: `${(f.size / 1024).toFixed(0)} KB`, mtime: iso(f.mtime) });
    }
    findings.push(makeFinding(
      'screenshot-pileup',
      `Screenshots pile up in ${path.basename(loc)}`,
      `${n} screenshots and screen recordings sit in ${tilde(loc, ctx.home)}, unfiled. ` +
      `Each one you keep or hunt for later costs a little time.`,
      evidence,
      { count: n, estMinutesPerInstance: 0.33, estHoursPerWeek: est, confidence: 0.9, oneShot: false }
    ));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 7 — downloads-entropy
// ---------------------------------------------------------------------------

function detectDownloadsEntropy(ctx) {
  const locs = new Set([path.join(ctx.home, 'Downloads')]);
  for (const r of ctx.roots) if (/^downloads$/i.test(path.basename(r))) locs.add(r);

  const findings = [];
  for (const loc of locs) {
    const loose = ctx.files.filter((f) => f.dir === loc); // top level only
    if (loose.length <= 60) continue;
    const n = loose.length;
    const est = estimateHours('downloads-entropy', { count: n });
    const sorted = newestFirst(loose);
    const evidence = [{ path: loc, detail: `${n} loose files at the top level`, mtime: iso(sorted[0].mtime) }];
    for (const f of sorted.slice(0, 4)) {
      evidence.push({ path: f.path, detail: `${(f.size / 1024).toFixed(0)} KB`, mtime: iso(f.mtime) });
    }
    findings.push(makeFinding(
      'downloads-entropy',
      'Loose files pile up in Downloads',
      `${n} files sit loose at the top level of ${tilde(loc, ctx.home)}. ` +
      `Finding anything means scanning the pile by eye.`,
      evidence,
      { count: n, estMinutesPerInstance: 15, estHoursPerWeek: est, confidence: 0.85, oneShot: false }
    ));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 8 — commit-drudgery (async: shells out to git, 3s timeout per repo)
// ---------------------------------------------------------------------------

function isGenericCommit(subject) {
  const t = subject.trim().toLowerCase();
  if (t.length < 8) return true;
  return /^(fix|wip|update|typo)\b[^a-z0-9]*$/.test(t) || /^\.+$/.test(t);
}

async function detectCommitDrudgery(ctx) {
  const findings = [];
  for (const repo of ctx.repos.slice(0, 30)) { // bound total git time
    const log = await ctx.gitLog(repo);
    if (!log || log.length < 30) continue;
    const n = log.length;
    const generic = log.filter((c) => isGenericCommit(c.subject));
    const rate = generic.length / n;
    if (rate < 0.4) continue;
    let minTs = Infinity, maxTs = -Infinity;
    for (const c of log) { if (c.ts < minTs) minTs = c.ts; if (c.ts > maxTs) maxTs = c.ts; }
    const spanWeeks = Math.max((maxTs - minTs) / WEEK_MS, 1);
    const commitsPerWeek = n / spanWeeks;
    const est = estimateHours('commit-drudgery', { rate, commitsPerWeek });
    const pct = Math.round(rate * 100);
    const samples = generic.slice(0, 3).map((c) => `"${c.subject.trim()}"`).join(', ');
    const evidence = [
      { path: repo, detail: `${pct}% of the last ${n} commit messages are tiny or generic`, mtime: iso(maxTs) },
      { path: repo, detail: `e.g. ${samples}`, mtime: iso(maxTs) },
    ];
    findings.push(makeFinding(
      'commit-drudgery',
      'You write throwaway commit messages',
      `${pct}% of the last ${n} commits in ${tilde(repo, ctx.home)} say "fix", "wip", or under 8 characters. ` +
      `The history cannot tell you what actually changed.`,
      evidence,
      { count: n, estMinutesPerInstance: 2, estHoursPerWeek: est, confidence: 0.8, oneShot: false }
    ));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 9 — csv-report-assembly
// ---------------------------------------------------------------------------

function detectCsvReportAssembly(ctx) {
  const byDirCsv = new Map();
  for (const f of ctx.files) {
    if (f.ext !== '.csv' || f.size > TEXT_READ_MAX) continue;
    if (ctx.claimed.has(f.path)) continue; // e.g. already a dated-recurrence series
    let arr = byDirCsv.get(f.dir);
    if (!arr) { arr = []; byDirCsv.set(f.dir, arr); }
    arr.push(f);
  }

  const findings = [];
  for (const [dir, csvs] of byDirCsv) {
    if (csvs.length < 4) continue;
    const byHeader = new Map();
    for (const f of csvs) {
      const text = ctx.readText(f);
      if (!text) continue;
      const header = text.split(/\r?\n/, 1)[0].trim().slice(0, 500);
      if (header.length < 8 || !header.includes(',')) continue; // needs to look like a real header row
      const hk = fnv1aHex(header);
      let g = byHeader.get(hk);
      if (!g) { g = { header, files: [] }; byHeader.set(hk, g); }
      g.files.push(f);
    }
    for (const g of byHeader.values()) {
      if (g.files.length < 4) continue;
      for (const f of g.files) ctx.claimed.add(f.path);
      const n = g.files.length;
      const spanWeeks = spanWeeksOf(g.files);
      const perWeek = (n - 1) / Math.max(spanWeeks, 1);
      const est = estimateHours('csv-report-assembly', { perWeek });
      const sorted = newestFirst(g.files);
      const headerPreview = g.header.length > 60 ? g.header.slice(0, 57) + '...' : g.header;
      const evidence = [{
        path: sorted[0].path, detail: `${n} CSVs share the header "${headerPreview}"`, mtime: iso(sorted[0].mtime),
      }];
      for (const f of sorted.slice(1, 6)) {
        evidence.push({ path: f.path, detail: 'same header row', mtime: iso(f.mtime) });
      }
      findings.push(makeFinding(
        'csv-report-assembly',
        'You assemble the same CSV report by hand',
        `${n} CSV files in ${tilde(dir, ctx.home)} share an identical header row. ` +
        `Each one is the same table rebuilt manually.`,
        evidence,
        { count: n, estMinutesPerInstance: 25, estHoursPerWeek: est, confidence: 0.8, oneShot: false }
      ));
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Detector 10 — scaffold-repetition
// ---------------------------------------------------------------------------

const SCAFFOLD_MARKERS = new Set([
  'index.html', 'style.css', 'styles.css', 'script.js', 'app.js', 'index.js',
  'main.js', 'server.js', 'package.json', 'tsconfig.json', 'index.ts',
  'main.py', 'app.py', 'requirements.txt',
]);

function detectScaffoldRepetition(ctx) {
  const bySig = new Map();
  for (const [dir, files] of ctx.byDir) {
    if (isUnderAnyRepo(dir, ctx.repos)) continue; // non-git project dirs only
    if (ctx.roots.includes(dir)) continue;        // a scan root is not a "project"
    const markers = [...new Set(files.map((f) => f.base.toLowerCase()))]
      .filter((b) => SCAFFOLD_MARKERS.has(b)).sort();
    if (markers.length < 2) continue;
    const sig = markers.join(' + ');
    let g = bySig.get(sig);
    if (!g) { g = { sig, dirs: [] }; bySig.set(sig, g); }
    g.dirs.push({ dir, newest: Math.max(...files.map((f) => f.mtime)) });
  }

  const findings = [];
  for (const g of bySig.values()) {
    if (g.dirs.length < 3) continue;
    const n = g.dirs.length;
    const est = estimateHours('scaffold-repetition', { dirCount: n });
    const sorted = g.dirs.slice().sort((a, b) => b.newest - a.newest);
    const evidence = sorted.slice(0, 6).map((d) => ({
      path: d.dir, detail: `starter fileset: ${g.sig}`, mtime: iso(d.newest),
    }));
    findings.push(makeFinding(
      'scaffold-repetition',
      'You scaffold the same project by hand',
      `${n} project folders start from the same fileset (${g.sig}). ` +
      `You rebuild that skeleton each time instead of generating it.`,
      evidence,
      { count: n, estMinutesPerInstance: 35, estHoursPerWeek: est, confidence: 0.65, oneShot: false }
    ));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// DETECTORS — spec order. Execution order differs slightly (see EXEC_ORDER):
// series detectors run first and "claim" their files so the same manual work
// is never billed twice across detectors.
// ---------------------------------------------------------------------------

const DETECTOR_META = {
  'version-chains':      { kind: 'recurring-draft',    title: 'Recurring draft agent' },
  'dated-recurrence':    { kind: 'recurring-draft',    title: 'Recurring draft agent' },
  'near-duplicate-text': { kind: 'template-extractor', title: 'Template extractor' },
  'untested-repos':      { kind: 'test-writer',        title: 'Test writer agent' },
  'undocumented-repos':  { kind: 'doc-writer',         title: 'README writer agent' },
  'screenshot-pileup':   { kind: 'file-organizer',     title: 'File organizer agent' },
  'downloads-entropy':   { kind: 'file-organizer',     title: 'File organizer agent' },
  'commit-drudgery':     { kind: 'changelog-agent',    title: 'Changelog agent' },
  'csv-report-assembly': { kind: 'report-assembler',   title: 'Report assembler agent' },
  'scaffold-repetition': { kind: 'scaffold-skill',     title: 'Scaffold skill' },
};

const DETECTORS = [
  { name: 'version-chains',      automation: DETECTOR_META['version-chains'],      run: detectVersionChains },
  { name: 'dated-recurrence',    automation: DETECTOR_META['dated-recurrence'],    run: detectDatedRecurrence },
  { name: 'near-duplicate-text', automation: DETECTOR_META['near-duplicate-text'], run: detectNearDuplicateText },
  { name: 'untested-repos',      automation: DETECTOR_META['untested-repos'],      run: detectUntestedRepos },
  { name: 'undocumented-repos',  automation: DETECTOR_META['undocumented-repos'],  run: detectUndocumentedRepos },
  { name: 'screenshot-pileup',   automation: DETECTOR_META['screenshot-pileup'],   run: detectScreenshotPileup },
  { name: 'downloads-entropy',   automation: DETECTOR_META['downloads-entropy'],   run: detectDownloadsEntropy },
  { name: 'commit-drudgery',     automation: DETECTOR_META['commit-drudgery'],     run: detectCommitDrudgery },
  { name: 'csv-report-assembly', automation: DETECTOR_META['csv-report-assembly'], run: detectCsvReportAssembly },
  { name: 'scaffold-repetition', automation: DETECTOR_META['scaffold-repetition'], run: detectScaffoldRepetition },
];

// Claim-producing detectors first so hours are never double-counted.
const EXEC_ORDER = [
  'dated-recurrence', 'csv-report-assembly', 'version-chains', 'near-duplicate-text',
  'untested-repos', 'undocumented-repos', 'screenshot-pileup', 'downloads-entropy',
  'commit-drudgery', 'scaffold-repetition',
];

// ---------------------------------------------------------------------------
// runScan
// ---------------------------------------------------------------------------

const METHODOLOGY =
  'score = clamp(round(100 - 9*hours), 4, 96); hours = sum of per-finding estimates, each capped; formulas in ESTIMATES table';

function clamp(x, lo, hi) { return Math.min(Math.max(x, lo), hi); }

async function runScan(opts = {}, onProgress) {
  const t0 = Date.now();
  const home = os.homedir();
  const stats = { files: 0, dirs: 0, repos: 0, textFilesSampled: 0, durationMs: 0, skipped: 0 };
  const roots = resolveRoots(opts.roots, home);

  // Throttled progress (~100ms); phase changes always emit.
  let lastEmit = 0, lastPhase = null;
  const emit = (phase, currentPath, force) => {
    if (typeof onProgress !== 'function') return;
    const now = Date.now();
    if (!force && phase === lastPhase && now - lastEmit < 100) return;
    lastEmit = now; lastPhase = phase;
    try {
      onProgress({ phase, filesSeen: stats.files, dirsSeen: stats.dirs, currentPath: currentPath || '' });
    } catch (e) { /* a broken progress callback must not kill the scan */ }
  };

  emit('walking', roots[0] || '', true);
  const { files, repos } = walk(roots, stats, emit);

  emit('analyzing', '', true);
  const ctx = buildContext(files, repos, roots, stats, home);
  const byName = new Map(DETECTORS.map((d) => [d.name, d]));
  const findings = [];
  for (const name of EXEC_ORDER) {
    emit('analyzing', name);
    try {
      const out = await byName.get(name).run(ctx);
      if (Array.isArray(out)) findings.push(...out);
    } catch (e) {
      // One broken detector never kills the scan.
      try { process.stderr.write(`[latent] detector ${name} failed: ${e && e.message}\n`); } catch (_) {}
    }
  }

  findings.sort((a, b) => b.metrics.estHoursPerWeek - a.metrics.estHoursPerWeek);
  const hours = findings.reduce((s, f) => s + f.metrics.estHoursPerWeek, 0);
  stats.durationMs = Date.now() - t0;

  const scan = {
    generatedAt: new Date().toISOString(),
    roots,
    stats,
    score: {
      value: clamp(Math.round(100 - 9 * hours), 4, 96),
      recoverableHoursPerWeek: Math.round(hours * 10) / 10,
      methodology: METHODOLOGY,
    },
    findings,
  };
  emit('done', '', true);
  return scan;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { roots: null, out: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--roots=')) args.roots = a.slice(8).split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--roots' && argv[i + 1]) args.roots = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a.startsWith('--out=')) args.out = a.slice(6);
    else if (a === '--out' && argv[i + 1]) args.out = argv[++i];
  }
  return args;
}

if (require.main === module) {
  const args = parseArgs(process.argv.slice(2));
  const outPath = path.resolve(args.out || path.join(__dirname, 'scan.json'));
  const tty = process.stderr.isTTY;
  runScan({ roots: args.roots }, (p) => {
    const tail = p.currentPath.length > 56 ? '…' + p.currentPath.slice(-55) : p.currentPath;
    const line = `[latent] ${p.phase}  files:${p.filesSeen} dirs:${p.dirsSeen}  ${tail}`;
    process.stderr.write(tty ? '\r' + line.padEnd(110).slice(0, 110) : line + '\n');
  })
    .then((scan) => {
      fs.writeFileSync(outPath, JSON.stringify(scan, null, 2));
      if (tty) process.stderr.write('\n');
      process.stderr.write(
        `[latent] wrote ${outPath} — ${scan.findings.length} findings, ` +
        `${scan.score.recoverableHoursPerWeek} h/wk recoverable, leverage ${scan.score.value}/100\n`
      );
    })
    .catch((e) => {
      process.stderr.write(`[latent] scan failed: ${e && e.stack || e}\n`);
      process.exit(1);
    });
}

module.exports = { runScan, DETECTORS, ESTIMATES };
