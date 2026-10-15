# CrackGothGirlsMedium Knife MCP field notes

Target: `/home/chixin/Desktop/Crackme/CrackGothGirlsMedium.exe`

SHA-256: `7937ca87a6b7f9fb4ffa25f8bbe7193ae501bd4c381a11360812aa3b4ae5a99e`

Purpose: preserve observations from a real crackme session so the agent-facing
Knife workflow can be improved from concrete failures rather than synthetic
examples.

## Session baseline

- Knife 1.8.2 parsed a 64-bit PE console executable and recovered 786 functions.
- Static analysis completed without truncation.
- Session-status evidence:
  `ev-e615b4b0f2cb90fa6d94f35efaffb48214d67a0f5f4dc3be65036e75b5f7fdc4`.
- The main challenge routine is `0x140001000`.
- Its two principal indirect closures are `0x1400019b0` and `0x140003dd0`.
- The visible prompt is `Seven gates between you and the flag <3` followed by
  `Enter password:` and `Here you go:`.

## What worked

- `session_status` established content identity, coverage, limitations, and
  operation availability in one call.
- String cross-references found the main routine immediately.
- Import cross-references separated library-wide capability from concrete call
  sites.
- `audit --reachable` reduced the sink inventory to one low-severity checked
  allocation candidate.
- Decompilation recognized the Base64 encoder and SHA-256 implementation well
  enough to identify them semantically.
- Static path queries showed no resolved path from the challenge routine to
  `CreateProcessW` or `getaddrinfo`.

## Friction and suspected defects

- Several CLI selectors accept only a hexadecimal address even though another
  command has assigned the usual `sub_...` name to the same function.
- `headers` rejects PE input with an ELF-only error instead of providing a PE
  header view or a format-specific availability explanation.
- The pseudocode renderer occasionally loses argument/data-flow fidelity around
  wrappers and indirect calls; some wrappers appear to read their freshly
  allocated result object rather than the supplied input.
- Raw printable-string extraction produces many instruction-byte false
  positives such as register-save sequences.
- The path engine cannot resolve the function-object dispatch used by this
  sample. Empty paths to Base64/SHA-256 are therefore not evidence that the
  challenge does not use them.
- Very large decompile/disassembly results need semantic slicing or paging by
  basic block, address interval, expression, and data dependency. A full result
  for `0x1400019b0` is too large for a useful agent turn.
- `disassemble` silently caps a large function at 400 instructions. Selecting
  an address inside the same function returns the same prefix, so there is no
  MCP-native way to inspect the tail. The workaround was repeated 128-byte
  `read_bytes` calls followed by local decoding of those MCP-returned bytes.
- `read_bytes` caps output at 128 bytes even when a larger length is requested;
  the response should report the cap explicitly and return a continuation
  cursor or next address.
- `decompile` and `disassemble` require the argument name `selector`; an
  attempted `address` argument only returned `missing selector`. Accepting both
  names would make the API less brittle for agents.
- Pseudocode for the output closure omitted the literal assignments that build
  its 21-element ciphertext array. The disassembly retained them, but recovering
  such a common array-initialization pattern should be a decompiler priority.
- `paths_to` can include broad error/runtime paths that make an API look related
  to the challenge even when neither principal closure directly calls it.
- Crypto-signature hits should expose references and likely wrapper functions
  directly, avoiding separate manual address conversion and xref calls.

## Solve ledger

Observed:

- `0x140001000` reads a password, invokes `0x1400019b0`, performs further
  bitwise extraction, invokes `0x140003dd0`, and prints a derived result.
- `0x140006630` implements Base64 encoding.
- `0x140006b40` and `0x14000a530` implement SHA-256.
- The final flag is not present as a plaintext string.
- `0x1400019b0` enforces a 15-byte input and constructs
  `T[i] = password[i] XOR (7*i + 19)`.
- Direct gates recovered from the closure are:
  `password[0] + password[14] == 84`,
  `password[2] XOR password[12] == 53`,
  `password[6] + password[8] == 193`, `T[0] == 32`, `T[7] == 27`,
  `T[14] == 84`, and `sum(T) mod 256 == 80`.
- Three five-byte rolling hashes are computed with multipliers 31, 37, and 41.
  The hash triple `(10, 83, 219)` produces key bytes `f8 4f 46 47`.
- `0x140003dd0` contains ciphertext bytes
  `a8 07 1f 03 5d 12 19 12 57 11 2d 37 50 19 06 11 77 ca 15 ed 49`.
- Its loop emits byte `i` as
  `ciphertext[i] XOR ((key[i mod 4] + 3*i) AND 0xff)`.
- Decrypting with `f8 4f 46 47` yields
  `PUSSYLANG{I_Love_Him}`.
- A printable password satisfying every recovered gate and producing that key
  is `3aaoCbr_OGafTH!`. The constraints are non-unique, so this is a solver
  witness, not necessarily the author's intended password.

Inferred:

- The executable contains a tagged-value interpreter/runtime and registers a
  broad standard-library surface. Process and networking helpers are probably
  generic facilities rather than part of the crackme path.
- The seven gates are encoded inside the large closure at `0x1400019b0` and use
  indirect function objects, loops, byte arrays, and numeric/bitwise operators.
- The recovered 21-byte plaintext is the flag: it has the challenge-language
  prefix and balanced braces, and every byte follows the observed decryption
  loop. This is a strong static conclusion, but was not confirmed by native
  execution because Wine is unavailable in this environment.

Unknown:

- The author's intended password; the gates admit multiple valid witnesses.
- Native runtime confirmation of the solver witness on Windows/Wine.
- Complete indirect call graph for the registered operation wrappers.

## Improvement backlog

High-value additions for an REA-style agent workflow:

1. Address-range/basic-block paging for `disassemble` and `decompile`.
2. First-class constant propagation through RIP-relative loads and tagged-value
   arithmetic, with an expression view for loop recurrences.
3. Indirect-call resolution for runtime function objects such as `len`, byte
   conversion, character conversion, and array indexing.
4. Automatic recognition and rendering of constructed constant arrays.
5. A constraint export/solve tool for recovered comparisons, modular sums,
   rolling hashes, and byte domains, returning a reproducible witness.
6. A small emulation/evaluation tool that can execute a recovered pure closure
   with supplied arguments and report intermediate values.
7. Evidence-bearing results for every analysis tool, not only session status,
   so reports can cite stable evidence IDs rather than retained-result IDs.

Key retained results:

- gate pseudocode: `result-986c3f94d51cf2054522f1614d7b15138a3e962ab13d79003a0b304231c6b0f1`
- gate disassembly prefix: `result-caac1802534c52856f5ebb35f9a61d25a55282e99961ee93610fecb5f4b1c52a`
- output pseudocode: `result-19dd37603c6f634ab0597eab9a78ea0d0566a36fdcc0590c087785c386c08e97`
- output disassembly prefix: `result-6f56a0cf62d932e154f5968b3c006b111bd3f4395c48c548d652c5c9f341a8c9`
- output analyst note: `result-ac39fd86fccc1d831e44ab51d2be1f35ffb0dbc677f1730ac353b2693d7a22f5`
- gate analyst note: `result-4e0d8daf8640ba3057ef5ea08d4d9efead26503f645096e65fd72a59935f37d6`
