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
netsherlock triage LOGFILE
netsherlock dashboard LOGFILE
netsherlock alert LOGFILE
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

## Traffic triage

`triage` ingests request records and flags likely attack traffic by request
*content and behavior*, never by source IP — an address proves nothing about
intent when attackers alias many IPs and legitimate and hostile clients look
identical. It accepts Apache/nginx combined/common access-log lines and
generic JSON-per-line records (`{"method":...,"url":...,"status":...,"user_agent":...,"ts":...}`).

```sh
netsherlock triage examples/sample-access.log
netsherlock triage access.log --json | jq '.summary'
```

Each flagged request gets a verdict, one or more short reasons, and a `0..1`
confidence score. Per-request signatures cover SQL injection, path traversal,
XSS, command injection, sensitive-path enumeration, and known scanner
User-Agents. Aggregate signals — auth brute-force (many failed authentications
against one endpoint) and abnormal request rate (a burst to one path in a short
window) — are grouped by target resource, not by client. Legitimate requests
are not reported; they are served.

Calibration knobs: `--window SECONDS` (bucket width, default 10), `--rate N`
(requests per window per path before "abnormal", default 20), and `--fails N`
(failed auths per window per path before "brute-force", default 5).

## Live dashboard

`dashboard` runs the same classifier as `triage` over a log and renders a
compact, refreshing board: request counts by category (SQLi, scanner,
brute-force, XSS, path-traversal, command-injection, sensitive-path,
rate-anomaly, and normal), the most recent flagged requests with their reason
and confidence, and the busiest source addresses by volume.

```sh
netsherlock dashboard examples/sample-access.log      # live, redraws every 2s
netsherlock dashboard /var/log/nginx/access.log --interval 1 --top 10
netsherlock dashboard examples/sample-access.log --once   # render once, no loop
```

It redraws every `--interval` seconds (default 2) until Ctrl-C; `--once` (and
piping to a non-terminal) renders a single frame. The source-address panel is
**display only** — NetSherlock never bans or scores a client by address, since
scanners, scoring services, and legitimate users share the same networks. The
same `--window`/`--rate`/`--fails` knobs apply.

## Alerting

`alert` tails a log (`tail -F` style) and POSTs a message to a Slack or Discord
incoming webhook each time a request is flagged above a confidence threshold.
It is **dry-run by default** — it prints what it would send and posts nothing
until you pass `--no-dry-run` with a webhook. A debounce collapses repeat
alerts per category+path so one scan is one alert, not five hundred.

```sh
# preview what would fire, over the whole file, without sending anything
netsherlock alert examples/sample-access.log --dry-run --from-start

# live: follow new lines and post to Slack (or Discord — the shape is inferred)
export NETSHERLOCK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ
netsherlock alert /var/log/nginx/access.log --no-dry-run --min-confidence 0.7
```

Options: `--webhook URL` (or the `NETSHERLOCK_WEBHOOK` env var),
`--webhook-format slack|discord|auto` (default `auto`, inferred from the URL),
`--min-confidence C` (default 0.5), `--debounce SECONDS` (default 60),
`--from-start` (scan the existing file, not just new lines), and `--once`
(process current contents and exit). Slack (`{"text":...}`) and Discord
(`{"content":...}`) JSON shapes are both supported; delivery uses the core
`HTTP::Tiny` (HTTPS needs `IO::Socket::SSL`).

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
