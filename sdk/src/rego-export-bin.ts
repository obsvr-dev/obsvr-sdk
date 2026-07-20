#!/usr/bin/env node
/**
 * `obsvr-export-rego` — write an OPA/Rego export bundle for a policy rule set.
 *
 * One-way interop export (the Obsvr SDK stays the source of truth). Reads a
 * rules JSON (an array of PolicyRule, or an object with a `rules` array — e.g.
 * the shape returned by GET /policies) and writes obsvr_policy.rego, data.json,
 * manifest.json, and README.md to an output directory.
 *
 *   obsvr-export-rego --rules policy.json --out ./rego-bundle
 *   obsvr-export-rego --rules policy.json            # writes to ./obsvr-rego-export
 *
 * Deliberately dependency-free (hand-rolled arg parsing), matching the SDK's
 * other bins — the SDK must stay lightweight.
 */

import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { exportToRego } from './policy/rego-export.js';
import type { PolicyRule } from './policy/rules.js';

function parseArgs(argv: string[]): { rules?: string; out: string; help: boolean } {
  const out = { rules: undefined as string | undefined, out: './obsvr-rego-export', help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') out.help = true;
    else if (a === '-r' || a === '--rules') out.rules = argv[++i];
    else if (a === '-o' || a === '--out') out.out = argv[++i];
  }
  return out;
}

const USAGE =
  'Usage: obsvr-export-rego --rules <file> [--out <dir>]\n' +
  '  --rules, -r  Path to a rules JSON (array of PolicyRule, or { rules: [...] })\n' +
  '  --out,   -o  Output directory (default ./obsvr-rego-export)';

export function runExportRego(argv: string[]): number {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(USAGE);
    return 0;
  }
  if (!opts.rules) {
    console.error('Missing --rules <file>.\n' + USAGE);
    return 2;
  }

  let rules: PolicyRule[];
  try {
    const parsed = JSON.parse(readFileSync(opts.rules, 'utf8'));
    rules = Array.isArray(parsed) ? parsed : parsed.rules;
    if (!Array.isArray(rules)) throw new Error('expected an array of rules or { rules: [...] }');
  } catch (err) {
    console.error(`Cannot read rules ${opts.rules}: ${(err as Error).message}`);
    return 2;
  }

  const bundle = exportToRego(rules);
  mkdirSync(opts.out, { recursive: true });
  writeFileSync(join(opts.out, 'obsvr_policy.rego'), bundle.rego);
  writeFileSync(join(opts.out, 'data.json'), bundle.data);
  writeFileSync(join(opts.out, 'manifest.json'), bundle.manifest);
  writeFileSync(join(opts.out, 'README.md'), bundle.readme);

  console.error(
    `Wrote Rego bundle to ${opts.out} (rules_hash ${bundle.rules_hash}, ` +
      `${JSON.parse(bundle.data).obsvr.rules.length} exported, ${bundle.delegated.length} delegated).`,
  );
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(runExportRego(process.argv.slice(2)));
}
