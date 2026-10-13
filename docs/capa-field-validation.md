# capa provider field validation

Validated using the official standalone capa 9.4.0 Linux release in a temporary
directory, without installing it system-wide.

- Release: https://github.com/mandiant/capa/releases/tag/v9.4.0
- Archive SHA-256: `07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4`
- Target: `CrackGothGirlsMedium.exe`
- Target SHA-256: `7937ca87a6b7f9fb4ffa25f8bbe7193ae501bd4c381a11360812aa3b4ae5a99e`

The first real MCP call exceeded the original 30-second deadline. Packaged
engine descendants retained output pipes, exposing a process-tree cleanup gap.
Unix providers now create their own process group and kill it at the deadline.
A regression with a helper retaining pipes returned in 0.11 seconds.

With `timeout_seconds: 120`, the actual MCP server returned 35 capability-rule
matches after 81.06 seconds. A continuation page returned in 0.14 seconds with
the identical cached report digest. Examples included file/process operations,
runtime linking, and XOR encoding. These are rule interpretations of static
features, not demonstrated execution or a malware verdict.

Evidence ID: `ev-bf1585413b25d66acc11715eb15d2995969d8d7c4144d67c8090297922c83418`.

Deep match-tree navigation remains outstanding. Windows descendant cleanup
still needs a job-object implementation; this Unix regression does not prove
equivalent cleanup on Windows.
