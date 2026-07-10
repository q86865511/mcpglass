#!/usr/bin/env node
// Differential conformance gate for mcpglass.
//
// Compares two runs of the official MCP conformance suite (`@modelcontextprotocol/
// conformance server -o <dir>`): one against a reference server connected *directly*
// (the baseline), and one against the *same* server reached *through* an mcpglass
// gateway (the proxied run). The proxy is a transparent tap, so the rule is simple:
//
//     proxied failures MUST be a subset of baseline failures.
//
// A scenario that passes when connected directly but fails through the proxy is a
// regression the proxy introduced — the script exits non-zero and names it. Failures
// present in *both* runs are the reference server's own conformance gaps (or suite
// bugs), not the proxy's fault; they are reported but never fail the gate.
//
// Usage:
//   node scripts/conformance-diff.mjs <baselineDir> <proxiedDir> [--label <name>]
//
// Each <dir> is a conformance `--output-dir`: one subdirectory per scenario named
// `server-<scenario>-<ISO-timestamp>/` containing a `checks.json` array. A scenario
// counts as failed when any of its checks has a status other than "SUCCESS".
//
// Exit codes: 0 = no proxy-induced failures; 1 = proxy-induced failure(s); 2 = bad
// invocation / unreadable input.

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';

function die(msg) {
  console.error(`conformance-diff: ${msg}`);
  process.exit(2);
}

function parseArgs(argv) {
  const positional = [];
  let label = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--label') {
      label = argv[++i];
      if (label === undefined) die('--label requires a value');
    } else if (a === '-h' || a === '--help') {
      console.log('Usage: node scripts/conformance-diff.mjs <baselineDir> <proxiedDir> [--label <name>]');
      process.exit(0);
    } else {
      positional.push(a);
    }
  }
  if (positional.length !== 2) {
    die('expected exactly two directories: <baselineDir> <proxiedDir>');
  }
  return { baselineDir: positional[0], proxiedDir: positional[1], label };
}

// Strip the `server-`/`client-` prefix and the trailing `-<ISO timestamp>` that the
// conformance CLI appends, leaving the bare scenario id (e.g. `tools-call-image`).
function scenarioFromDir(name) {
  const noTs = name.replace(/-\d{4}-\d{2}-\d{2}T[\d-]+Z$/, '');
  return noTs.replace(/^(server|client)-/, '');
}

// Read an output-dir into a Map<scenario, { failed, checks }>. When the same
// scenario ran more than once (its dir name carries a unique timestamp), the runs
// are merged: the scenario is failed if any run failed.
function readRun(dir, which) {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    die(`${which} directory not found or not a directory: ${dir}`);
  }
  const result = new Map();
  const entries = readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory());
  for (const e of entries) {
    const checksPath = join(dir, e.name, 'checks.json');
    if (!existsSync(checksPath)) continue;
    let checks;
    try {
      checks = JSON.parse(readFileSync(checksPath, 'utf8'));
    } catch (err) {
      die(`could not parse ${checksPath}: ${err.message}`);
    }
    if (!Array.isArray(checks)) die(`${checksPath} is not a JSON array`);
    const scenario = scenarioFromDir(e.name);
    const failed = checks.some((c) => c && c.status !== 'SUCCESS');
    const prev = result.get(scenario);
    if (prev) {
      prev.failed = prev.failed || failed;
      prev.checks.push(...checks);
    } else {
      result.set(scenario, { failed, checks: [...checks] });
    }
  }
  if (result.size === 0) {
    die(`${which} directory ${dir} contained no scenario results (no */checks.json)`);
  }
  return result;
}

function failingSet(run) {
  return new Set([...run].filter(([, v]) => v.failed).map(([k]) => k));
}

function firstError(run, scenario) {
  const v = run.get(scenario);
  if (!v) return '';
  const bad = v.checks.find((c) => c && c.status !== 'SUCCESS');
  return bad && bad.errorMessage ? bad.errorMessage : (bad ? bad.status : '');
}

function main() {
  const { baselineDir, proxiedDir, label } = parseArgs(process.argv.slice(2));
  const baseline = readRun(baselineDir, 'baseline');
  const proxied = readRun(proxiedDir, 'proxied');

  const baseFail = failingSet(baseline);
  const proxFail = failingSet(proxied);

  const tag = label ? ` [${label}]` : '';
  const line = '─'.repeat(60);
  console.log(line);
  console.log(`Differential conformance diff${tag}`);
  console.log(line);
  console.log(`  baseline: ${baseline.size} scenarios, ${baseFail.size} failing`);
  console.log(`  proxied:  ${proxied.size} scenarios, ${proxFail.size} failing`);

  // Scenario coverage mismatch is a harness problem worth surfacing, but only a
  // proxied scenario *missing from the baseline* can hide a proxy regression, so
  // that case feeds the gate below (a baseline-only scenario cannot).
  const onlyProxied = [...proxied.keys()].filter((s) => !baseline.has(s));
  const onlyBaseline = [...baseline.keys()].filter((s) => !proxied.has(s));
  if (onlyProxied.length || onlyBaseline.length) {
    console.log('');
    console.log('  ⚠ scenario coverage differs between runs:');
    if (onlyBaseline.length) console.log(`      only in baseline: ${onlyBaseline.join(', ')}`);
    if (onlyProxied.length) console.log(`      only in proxied:  ${onlyProxied.join(', ')}`);
  }

  // Pre-existing failures: fail in baseline too. Informational — the reference
  // server's / suite's own gaps, not something the proxy did.
  const preExisting = [...proxFail].filter((s) => baseFail.has(s)).sort();
  if (preExisting.length) {
    console.log('');
    console.log(`  ℹ ${preExisting.length} pre-existing failure(s) (fail in BOTH runs — not the proxy's fault):`);
    for (const s of preExisting) console.log(`      - ${s}`);
  }

  // Baseline failures the proxied run did NOT reproduce. Not a gate concern, but
  // worth noting: usually the gateway adding a protection the bare server lacks
  // (e.g. DNS-rebinding Origin/Host gating), occasionally suite flakiness.
  const clearedByProxy = [...baseFail].filter((s) => !proxFail.has(s)).sort();
  if (clearedByProxy.length) {
    console.log('');
    console.log(`  ℹ ${clearedByProxy.length} scenario(s) failed baseline but PASSED proxied (proxy adds a protection, or flaky):`);
    for (const s of clearedByProxy) console.log(`      - ${s}`);
  }

  // The gate: scenarios that fail through the proxy but pass (or were absent) at
  // baseline. Any such scenario is a regression the proxy introduced.
  const proxyInduced = [...proxFail].filter((s) => !baseFail.has(s)).sort();
  console.log('');
  if (proxyInduced.length === 0) {
    console.log('  ✓ PASS — proxied failures are a subset of baseline failures.');
    console.log('           The gateway introduced no new conformance failures.');
    console.log(line);
    process.exit(0);
  }
  console.log(`  ✗ FAIL — ${proxyInduced.length} proxy-induced failure(s) (pass direct, fail through gateway):`);
  for (const s of proxyInduced) {
    const missing = !baseline.has(s) ? '  [absent from baseline run]' : '';
    console.log(`      - ${s}${missing}`);
    const err = firstError(proxied, s);
    if (err) console.log(`          ${String(err).split('\n')[0].slice(0, 140)}`);
  }
  console.log(line);
  process.exit(1);
}

main();
