#!/usr/bin/env node
// Builds data/loldrivers.json — a compact, offline snapshot of the
// Living-Off-the-Land Drivers project (https://www.loldrivers.io) suitable for
// `knife drv --known` matching by SHA-256.
//
// Source: the project's public JSON API, fetched once during development.
// Usage: node scripts/gen-loldrivers.mjs <full.json> [out.json]

import fs from 'node:fs';

const src = process.argv[2];
const out = process.argv[3] || 'data/loldrivers.json';

if (!src) {
  console.error('usage: node scripts/gen-loldrivers.mjs <loldrivers-full.json> [out.json]');
  process.exit(2);
}

const records = JSON.parse(fs.readFileSync(src, 'utf8'));
const outarr = [];
const seen = new Set();

for (const rec of records) {
  const category = String(rec.Category || '').toLowerCase();
  const samples = rec.KnownVulnerableSamples || [];
  for (const s of samples) {
    const sha = String(s.SHA256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(sha)) continue;
    if (seen.has(sha)) continue;
    seen.add(sha);
    const sigs = Array.isArray(s.Signatures)
      ? s.Signatures
      : s.Signatures && typeof s.Signatures === 'object'
        ? [s.Signatures]
        : [];
    outarr.push({
      sha256: sha,
      file: s.OriginalFilename || s.Filename || '',
      vendor: s.Company || s.Publisher || '',
      product: s.Product || '',
      category, // 'malicious' | 'vulnerable'
      // The signing publisher, when loldrivers catalogued a certificate.
      signer: sigs.flatMap((x) => x.Signer || []).map((x) => x.Issuer || '').filter(Boolean).join(' | '),
    });
  }
}

outarr.sort((a, b) => a.sha256.localeCompare(b.sha256));
fs.writeFileSync(out, JSON.stringify(outarr, null, 1));
console.log(`wrote ${out}: ${outarr.length} vulnerable-driver samples`);