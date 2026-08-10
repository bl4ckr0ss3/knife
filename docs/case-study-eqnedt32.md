# Case study: finding CVE-2017-11882 with knife

CVE-2017-11882 is a stack buffer overflow in the Microsoft Office Equation
Editor (`EQNEDT32.EXE`). It was exploited in the wild for years, and the
component is a good test of a static bug finder: it is a real, shipped,
stripped 32-bit binary, not a teaching example. This walks the same four
commands a researcher would run, on the actual vulnerable binary, and shows
knife landing on the vulnerable function.

The sample used here is the vulnerable build with SHA-256
`e18c02ba480e83489976314a0a79441108faf4d246292eba1eadd36ce4fc6acd`. knife never
executes it; every command below reads the bytes on disk.

## 1. What is it protected by?

```
$ knife sec EQNEDT32.EXE

§ MITIGATIONS
  [-] ASLR                 disabled   DYNAMIC_BASE clear, preferred base 0x400000
  [-] DEP / NX             disabled   NX_COMPAT clear
  [-] stack cookies (/GS)  disabled   no __security_cookie in the load config
  [-] CFG                  disabled   GUARD_CF clear
  [-] SafeSEH              disabled   no SEH handler table
  [-] W^X                  disabled   section .idata is writable and executable
  BARE   exposure score 20 · 6 of 7 mitigations missing or weakened
```

Nothing is turned on. No ASLR, so every address is known ahead of time; no
stack cookie, so a linear overflow reaches the return address unchecked; no DEP,
so injected code runs directly. This is the environment an overflow needs, and
it is why this bug was so reliably exploitable.

## 2. Which call sites look wrong?

```
$ knife audit EQNEDT32.EXE

§ AUDIT (7 FINDINGS)
  [-] stack-overflow   lstrcpyA  FMDFontListEnum @ 0x4212c2  ← reachable
      unbounded copy of a runtime value into a stack buffer (classic overflow)
  [-] stack-overflow   lstrcpyA  sub_41264b      @ 0x412803  ← reachable
      unbounded copy of a runtime value into a stack buffer (classic overflow)
  [-] stack-overflow   lstrcpyA  sub_41388b      @ 0x413935  ← reachable
      unbounded copy of a runtime value into a stack buffer (classic overflow)
  [-] alloc-overflow   ...       sub_44db10      @ 0x44dcbb  ← reachable
  ... 7 findings, all high severity ...
```

`audit` reads each dangerous call's arguments and keeps only the sites whose
provenance matches a bug pattern. On this binary all seven findings are high
severity: three `lstrcpyA` calls copying a runtime value into a fixed stack
buffer, and more. The first is in a function whose own name, `FMDFontListEnum`,
survived stripping, and CVE-2017-11882 is a font-name overflow. That is the one
to read first.

## 3. Confirm it

```
$ knife dis EQNEDT32.EXE --func FMDFontListEnum

  0000004212b7  mov eax, [ebp+8]        ; the attacker-controlled record
  0000004212ba  add eax, 0x1c           ; + 0x1c: the font name field
  0000004212bd  push eax                ; src = font name
  0000004212be  lea eax, [ebp-0x28]     ; dst = a 0x28-byte stack buffer
  0000004212c1  push eax
  0000004212c2  call dword ptr [0x466790]  ; KERNEL32!lstrcpyA
```

This is the vulnerability. A font name is read out of the attacker-controlled
equation record at `[ebp+8]+0x1c` and copied with `lstrcpyA`, which has no length
argument, into a 40-byte stack buffer at `[ebp-0x28]`. A font name longer than
40 bytes overruns the buffer and the saved return address, and step 1 already
showed there is no stack cookie in the way. That is CVE-2017-11882.

The decompiler makes the same point at a glance, with the frame slots named and
the control flow structured:

```
$ knife pseudo EQNEDT32.EXE --func FMDFontListEnum

  sub_421294() {
      if (arg_10 == 0x4) {
      loc_4212b7:
          lstrcpyA(&var_28, arg_8 + 0x1c);   // 40-byte buffer <- attacker data
          ...
          sub_421054(&var_28);
      } else {
          if (arg_10 == 0x2) {
              goto loc_4212b7;
          }
      }
      eax = 0x1;
      return eax;
  }
```

`var_28` is the 40-byte local, `arg_8` the equation record, and the copy has no
bound. The two conditions that reach the copy (`arg_10 == 4` or `== 2`) come out
as a real branch, with a single `goto` for the short-circuit that a compiler
emitted as one shared block.

The other two findings are the same shape in `sub_41264b` (an `lstrcpyA` of a
function argument into a `[ebp-0x64]` stack buffer). `EQNEDT32.EXE` carried a
family of these overflows, later assigned CVE-2018-0802 and CVE-2018-0798, so
more than one of knife's findings points at real, separately-patched bugs.

## What made this work

- **Coverage.** The binary is stripped, and the vulnerable code is reached
  through the equation-record dispatch, not a direct call chain. knife recovers
  it from the PE structure rather than from control flow alone, so the function
  is there to analyze.
- **Argument provenance across the 32-bit ABI.** `EQNEDT32.EXE` is 32-bit and
  passes its arguments on the stack. knife reads the `push`es to recover the
  copy destination (a stack buffer) and the source (a runtime value), which is
  what turns a bare "there is an lstrcpy here" into "this is a stack overflow of
  attacker data."
- **Honest ranking.** knife reports the pattern; the researcher confirms it in
  the disassembly. `audit` does not claim to know the CVE number. It puts the
  three call sites that look exploitable at the top of a short list, and the
  disassembly does the rest.

## Reproducing

```bash
knife sec  EQNEDT32.EXE
knife audit EQNEDT32.EXE
knife dis  EQNEDT32.EXE --func FMDFontListEnum
```

Any build of `EQNEDT32.EXE` with the hash above will produce the same output.
knife is static throughout: it never runs the target.
