# NetSherlock

NetSherlock is a general-purpose network troubleshooting CLI written in
Perl. It gathers evidence from ordinary Linux and macOS hosts, correlates
related observations, and explains plausible causes without claiming more
than the evidence establishes.

The internal pipeline is:

```text
measurement -> structured evidence -> diagnosis -> presentation
```

Network modules do not format terminal output. The diagnosis engine does not
parse human-readable text. The reporter performs no network operations.

## Requirements

- Perl 5.16 or newer
- Standard operating-system networking interfaces
- No mandatory non-core CPAN dependencies
- `traceroute` for the `trace` command (the command reports a useful failure
  if it is not installed)

## Install and run from a checkout

```sh
perl Makefile.PL
make test
make install

netsherlock --help
netsherlock --version
```

You can also run the checkout directly:

```sh
./bin/netsherlock port example.com 443
```

## Commands

```text
netsherlock ping HOST
netsherlock port HOST PORT
netsherlock dns HOST
netsherlock trace HOST
netsherlock inspect CONFIG
```

Every command has its own help page, for example
`netsherlock port --help`.

Useful options:

- `--json` emits structured output suitable for `jq`.
- `--timeout SECONDS` bounds network operations.
- `--max-hops N` limits `trace` (default 30).
- `--verbose` writes measurement steps to stderr.
- `--quiet` suppresses individual human-readable observations while keeping
  the diagnosis.

Example:

```sh
netsherlock port database.example.com 5432 --verbose
netsherlock dns example.com --json | jq '.results'
```

Normal output separates `Observed` facts from `Possible explanations` and
`Investigate next` suggestions. A refusal means that the destination
actively rejected the connection; it does not prove which service or
firewall configuration produced that response.

## Structured statuses

Results contain `check`, `target`, `success`, and an explicit `status`, with
optional latency, error, and check-specific detail. Common statuses include:

```text
success
 timeout
connection_refused
dns_failure
host_unreachable
network_unreachable
permission_denied
unsupported
skipped
unknown
```

A failed ping is not interpreted as proof that a host is down. For example,
when TCP succeeds while the reachability probe times out, NetSherlock reports
that ICMP or the selected probe may be filtered or unsupported.

## Configuration inspection

`inspect` accepts JSON or the small YAML subset used by
`examples/network.yml`. The first configuration implementation runs checks
from `local` to named hosts using TCP:

```yaml
hosts:
  web:
    address: 192.168.1.20
checks:
  - from: local
    to: web
    protocol: tcp
    port: 443
```

Remote `from` values are represented as unsupported evidence until the
explicit SSH phase is implemented. Configuration values are treated as data;
NetSherlock does not interpolate them into shell commands. A malformed or
unsupported configuration exits with code `2`.

## Exit codes

- `0` — requested diagnostic succeeded
- `1` — a network or service failure was observed
- `2` — invalid command, arguments, or configuration
- `3` — NetSherlock internal error

## Tests

Tests use localhost, temporary TCP listeners, injected resolver/connector
fixtures, and deterministic traceroute text. They do not require public
Internet services.

```sh
make test
# or
prove -Ilib -v t
```

## Safety and scope

NetSherlock is read-only by default. It never changes routes, interfaces,
firewalls, DNS configuration, services, packages, or SSH configuration, and
it never requests or stores passwords. Remote diagnostics, parallel checks,
topology reasoning, historical comparison, and a TUI are future layers over
the same evidence model.
