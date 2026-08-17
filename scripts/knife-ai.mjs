// knife-ai — turn knife's static analysis into an LLM-written report.
//
// Runs the knife command line over a binary (everything with --json), bundles
// the outputs, and asks an LLM — by default the same DeepSeek family OpenCode
// uses, through OpenRouter — to write a structured reverse-engineering report.
// The bundle can be dumped without the LLM (--raw) and pasted into any agent.
//
// Usage:
//   node scripts/knife-ai.mjs target.exe
//   node scripts/knife-ai.mjs target.exe --model openai/deepseek/deepseek-v4-flash-0731
//   node scripts/knife-ai.mjs target.exe --raw > bundle.json
//   node scripts/knife-ai.mjs target.exe --out report.md
//
// The API key comes from OPENROUTER_API_KEY, or falls back to the key OpenCode
// uses in ~/.config/opencode/opencode.jsonc (provider.openai.apiKey).

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const DEFAULT_KNIFE = join(here, "..", "target", "release", "knife.exe");
const KNIFE = process.env.KNIFE || (existsSync(DEFAULT_KNIFE) ? DEFAULT_KNIFE : "knife");
const API = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_MODEL = "deepseek/deepseek-v4-flash-0731";
// Knife passes are independent subprocesses that each re-load the file, so
// they run concurrently. Tuned for a desktop CPU; lower it on fewer cores.
const CONCURRENCY = 4;
const execFileAsync = promisify(execFile);

const args = process.argv.slice(2);
const file = args[0];
const model = flag(args, "--model") || DEFAULT_MODEL;
const outPath = flag(args, "--out");
const rawOnly = args.includes("--raw");
if (!file) {
  console.error("usage: knife-ai.mjs FILE [--model M] [--out F] [--raw]");
  process.exit(2);
}

// The knife commands whose JSON feeds the report. The caps keep the prompt
// bounded on big binaries; 100k chars of knife output is far more than the
// report needs.
const PASSES = [
  ["info", ["info", file, "--json"], 40_000],
  ["hashes", ["hashes", file, "--json"], 3_000],
  ["sec", ["sec", file, "--json"], 10_000],
  ["caps", ["caps", file, "--json"], 10_000],
  ["sections", ["sections", file, "--json"], 10_000],
  ["imports", ["imports", file, "--json"], 25_000],
  ["exports", ["exports", file, "--json"], 25_000],
  ["strings", ["strings", file, "--min", "6", "--json"], 25_000],
  ["iocs", ["iocs", file, "--json"], 20_000],
  ["scan", ["scan", file, "--json"], 10_000],
  ["audit", ["audit", file, "--json"], 40_000],
  ["sinks", ["sinks", file, "--json"], 40_000],
  ["drv", ["drv", file, "--json"], 60_000],
];

function flag(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

function apiKey() {
  if (process.env.OPENROUTER_API_KEY) return process.env.OPENROUTER_API_KEY;
  const cfg = join(homedir(), ".config", "opencode", "opencode.jsonc");
  try {
    const raw = readFileSync(cfg, "utf8");
    // Strip only whole-line comments: URLs inside values contain `//` and
    // must survive.
    const stripped = raw
      .split("\n")
      .filter((l) => !/^\s*\/\//.test(l))
      .join("\n")
      .replace(/\/\*[\s\S]*?\*\//g, "");
    const key = JSON.parse(stripped)?.provider?.openai?.apiKey;
    if (key) return key;
  } catch {}
  console.error(
    "no API key: set OPENROUTER_API_KEY or put provider.openai.apiKey in ~/.config/opencode/opencode.jsonc"
  );
  process.exit(1);
}

function runKnife(argv) {
  return execFileAsync(KNIFE, argv, { encoding: "utf8", maxBuffer: 1 << 30 })
    .then(({ stdout }) => stdout)
    .catch((e) => `(knife failed: ${e.message.split("\n")[0]})`);
}

// Keep every pass readable but bounded: cap the character count and say so.
function cap(text, limit) {
  if (text.length <= limit) return text;
  return text.slice(0, limit) + `\n[… ${text.length - limit} more chars truncated]`;
}

// Run the passes with a small worker pool instead of one after another: each
// knife subprocess loads the file and re-runs part of the engine, so the
// passes are independent by construction and parallelise cleanly.
async function bundle() {
  const results = new Array(PASSES.length);
  let next = 0;
  const worker = async () => {
    while (next < PASSES.length) {
      const i = next++;
      const [label, argv, limit] = PASSES[i];
      process.stderr.write(`  [${i + 1}/${PASSES.length}] knife ${argv[0]} ${argv[1]}\n`);
      results[i] = `## ${label}\n${cap((await runKnife(argv)).trim(), limit)}`;
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, PASSES.length) }, worker));
  return results.join("\n\n");
}

const SYSTEM = `You are a senior reverse engineer and malware analyst writing the final
report for a static analysis session that used "knife", a PE/ELF/Mach-O
triage and audit tool. The data below is knife's own output: verdicts,
mitigations, imports, exports, strings, IOCs, crypto scan, and the ranked
sink/audit findings.

Write a report in Markdown with this structure:
1. **Verdict** — one confident line (benign tool / emulator / crack loader /
   malware / unclear), separating facts from hypotheses.
2. **Evidence** — the signals that decide the verdict: signatures, sections,
   exports masquerading, embedded frameworks, odd strings, IOCs, packing.
3. **Attack surface** — mitigations, notable imports, and the audit/sinks
   findings worth a look, citing addresses in 0x... form.
4. **Next steps** — 3-5 concrete follow-ups (dynamic analysis in a VM, the
   function names to disassemble, hashes to check against VirusTotal, ...).

Rules: never invent evidence; if a signal is ambiguous say so; prefer
specific addresses and names from the data over generalities. Copy hashes
(md5/sha1/sha256/imphash), thumbprints, IOCTL codes, and address ranges
verbatim from the data — never reconstruct, truncate, or re-derive them.

Kernel drivers: when the target is a Windows kernel driver (subsystem
"native" or a .sys in the drv pass), add a dedicated **Driver / BYOVD
surface** section that reads the drv pass and answers:
  - identity (module, entry / DriverEntry, bitness)
  - devices and \\DosDevices\\ symbolic links exposed
  - IRP dispatch table (which IRP_MJ_* are handled) and any IOCTL codes,
    calling out METHOD_NEITHER / METHOD_IN_DIRECT / METHOD_OUT_DIRECT and
    giving each code in 0x... form
  - the kernel primitives from the drv pass (physical-memory maps, arbitrary
    kernel R/W, driver-loading, registry/process, callbacks) with their
    classes, severities, and call addresses
  - any "known vulnerable driver" match and the signing subjects/thumbprints.
Be explicit about whether the primitives are reachable from user mode via the
IOCTL surface. Keep it under ~70 lines.`;

async function main() {
  process.stderr.write(`bundling knife output for ${file}\n`);
  const data = await bundle();
  process.stderr.write(`bundle: ${(data.length / 1024).toFixed(0)} KB\n`);
  if (rawOnly) {
    process.stdout.write(data);
    return;
  }

  const user = `Target: ${file}\nHere is the knife output, labelled by command. Write the report.\n\n${data}`;
  process.stderr.write(`asking ${model} …\n`);
  const res = await fetch(API, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey()}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: SYSTEM },
        { role: "user", content: user },
      ],
      temperature: 0.2,
      max_tokens: 4096,
    }),
  });
  const body = await res.json();
  if (!res.ok || body.error) {
    console.error("API error:", JSON.stringify(body.error || body).slice(0, 500));
    process.exitCode = 1;
    return;
  }
  const report = body.choices?.[0]?.message?.content ?? "(no content)";
  if (outPath) writeFileSync(outPath, report, "utf8");
  process.stdout.write(report + "\n");
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
