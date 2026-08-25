# Contributing to NetSherlock

NetSherlock is an independent, general-purpose network troubleshooting CLI
written in Perl. Contributions should keep it useful on ordinary Linux and
macOS hosts, VMs, containers, Raspberry Pis, and cloud machines.

Do not copy or depend on university course material, testbed scripts,
topology definitions, commands, documentation, or assignment implementations.

## Engineering guidelines

- Keep the pipeline separated:
  `measurement -> evidence -> diagnosis -> presentation`.
- Measurements should return structured `NetSherlock::Result` objects rather
  than formatting terminal output.
- Diagnosis should consume structured evidence and distinguish observations
  from interpretations.
- Human-readable conclusions must not claim more than the evidence proves.
- Reporters should format existing results and never perform network
  operations.
- Diagnostics must remain non-destructive and local-first by default.
- Treat hosts, ports, paths, and configuration values as untrusted input.
- Avoid shell invocation and never interpolate user-controlled values into
  commands.
- Any future remote operation must be explicitly authorized,
  non-destructive, timeout-bounded, safely escaped, and recorded in evidence.
- Production Perl should use `strict` and `warnings`, favor core modules, and
  remain understandable rather than clever.

## CLI and tests

The supported commands are `ping`, `port`, `dns`, `trace`, and `inspect`.
Each command should provide command-specific help. Preserve JSON output and
the documented exit codes:

- `0` — requested diagnostic succeeded
- `1` — a network or service failure was observed
- `2` — invalid input or configuration
- `3` — internal error

Tests must be deterministic and must not depend on arbitrary public Internet
services. Prefer localhost, temporary TCP servers, injected resolver or
connector behavior, and fixed output fixtures. Add both success and failure
coverage, and update the README and CLI help when the user-facing contract
changes.

Run the test suite with:

```sh
make test
```

or:

```sh
prove -Ilib -v t
```
