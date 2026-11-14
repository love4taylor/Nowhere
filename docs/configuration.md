# Configuration

Configure listeners, transport selection and a fixed exit with service URLs.

## Contents

- [Role URLs](#role-urls)
- [Endpoints](#endpoints)
- [Share links](#share-links)
- [Portal URL](#portal-url)
- [Vector URL](#vector-url)
- [Egress URL](#egress-url)
- [Built-in DNS](#built-in-dns)
- [Parsing configuration](#parsing-configuration)
- [Parameter overview](#parameter-overview)
- [Rate limits](#rate-limits)
- [Runtime environment](#runtime-environment)

## Role URLs

| Role | URL | Purpose |
|---|---|---|
| Portal | `portal://KEY@ENDPOINT` | TLS/QUIC listeners and one fixed exit |
| Vector | `vector://KEY@ENDPOINT?in=HOST:PORT` | Local SOCKS5 ingress and one connection carrier to Portal |
| Egress | `egress://KEY@ENDPOINT` | TLS or QUIC registration and target access |

`KEY` is percent-decoded once and used as text bytes. All three roles require
exactly 32 lowercase hexadecimal characters. Generate a key with
`nowhere generate-key` and use the same value on the peers. Service URLs do not
accept a password component or display-name fragment.

`ENDPOINT` selects the host, port and transport. Query parameters follow `?`
and are separated by `&`.

## Endpoints

All roles use the same endpoint grammar, with different carrier limits:

| ENDPOINT form | Portal | Vector | Egress |
|---|---|---|---|
| `HOST:PORT` | TLS and QUIC on the same port | TLS | QUIC |
| `HOST/tcp:PORT` | TLS listener | TLS connection | TLS connection |
| `HOST/udp:PORT` | QUIC listener | QUIC connection | QUIC connection |
| `HOST/tcp:PORT/udp:PORT` | Separate TLS and QUIC listener ports | Unsupported | Unsupported |

Portal paths declare one or two carriers. Vector paths declare exactly one
carrier; Egress paths also declare exactly one carrier. Both TLS and QUIC carry
TCP and UDP business Flows.

Each carrier may specify an address family:

| Carrier | Transport | Address family |
|---|---|---|
| `tcp` | TLS | IPv4 or IPv6 |
| `tcp4` | TLS | IPv4 only |
| `tcp6` | TLS | IPv6 only |
| `udp` | QUIC | IPv4 or IPv6 |
| `udp4` | QUIC | IPv4 only |
| `udp6` | QUIC | IPv6 only |

Use a DNS name, IPv4 address or bracketed IPv6 address for `HOST`. Portal also
accepts `*` for wildcard listeners. Vector and Egress require a concrete host.
A concrete IP must match the carrier's address family.
Ports are decimal integers in `1..=65535`.

Do not combine an authority port with a carrier path. Paths do not accept empty
segments, dot segments or a trailing slash. Portal's two carriers may appear in
either order, but TCP and UDP may each be declared only once, including their
family-specific forms.

Examples:

```text
portal://KEY@*:2000
portal://KEY@*/tcp4:2000/udp6:2001
vector://KEY@relay.example/tcp:2000?in=127.0.0.1:1080
vector://KEY@relay.example/udp:2001?in=127.0.0.1:1080
egress://KEY@[2001:db8::1]/udp6:2001
```

Unrestricted wildcard Portal listeners may omit an unavailable family with a
diagnostic on stderr. Explicit families and concrete binds fail on errors. See
[network exposure](platforms.md#network-exposure) for socket and firewall rules.

## Share links

Share links use a compact host and port:

```text
nowhere://KEY@HOST:PORT
nowhere://KEY@HOST:PORT?net=udp&morph=1#NAME
```

Share links do not accept carrier paths. Use a concrete DNS name, IPv4 address
or bracketed IPv6 address. A display name as `#NAME` is recommended.
Percent-encode spaces and reserved characters in names.

Optional parameters:

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `net` | `tcp` or `udp` | `tcp` | Client carrier: TLS or QUIC |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |

The `fingerprint` command additionally accepts `sni` and requires an explicit
`morph=0` or `morph=1`. It always inspects TCP/TLS, even when the link specifies
`net=udp`. See [Operations](operations.md#diagnose-target-setup). Client
applications define their own support for additional share-link parameters.

## Portal URL

```text
portal://KEY@ENDPOINT[?out=EXIT]
```

Portal listens on `ENDPOINT` and uses one fixed `out` for all Flows.

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `out` | `direct`, `egress` or `[USER:PASS@]HOST:PORT` | `direct` | Direct target access, registered Egress or a SOCKS5 upstream |
| `prefer` | `ipv4`, `ipv6` or `default` | `default` | Address family tried first for DNS-resolved Portal outbound connections |
| `tcp-concurrent` | `0` or `1` | `0` | Race all eligible DNS addresses for TCP Flows and use the first successful connection |
| `tls` | `1` or `2` | `1` | Generated certificate (`1`) or supplied PEM files (`2`) for TLS and QUIC |
| `crt` | Certificate-chain PEM path | Absent | Required exactly when `tls=2` |
| `key` | Private-key PEM path | Absent | Required exactly when `tls=2` |
| `dial` | IP literal or `auto` | `auto` | Outbound source binding; an IP restricts connections to its address family |
| `dial4` | IPv4 literal or `auto` | `auto` | IPv4 outbound source binding |
| `dial6` | IPv6 literal or `auto` | `auto` | IPv6 outbound source binding; IPv4-mapped addresses are invalid |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |
| `rate` | `0..=2147483647` Mbps | `0` | Vector-to-Target upload limit; `0` disables it |
| `etar` | `0..=2147483647` Mbps | `0` | Target-to-Vector download limit; `0` disables it |

`out=egress` accepts Egress on any enabled TLS or QUIC listener and conflicts
with explicit `dial`, `dial4`, `dial6`, `prefer` or `tcp-concurrent`, including their default values.
See [Egress](egress.md) for registration and offline behavior.

### Target source selection

`dial` is mutually exclusive with `dial4` and `dial6`. In the family-specific
form, an omitted family uses `auto`. Explicit source binding errors fail the
dial; they do not trigger an unbound retry. Portal applies these settings to
its own outbound work, including connections to a SOCKS5 upstream.

`prefer=ipv4` or `prefer=ipv6` tries DNS addresses of the selected family first,
preserving resolver order within each family. Connection failures can fall back
to the other family within the same dial timeout. `prefer=default` (or omission)
preserves resolver order. Literal target IPs and source address restrictions
still apply. With a SOCKS5 upstream, preference affects the proxy and UDP relay
addresses resolved by Portal; target domains are sent to the proxy unchanged.

`tcp-concurrent=1` starts TCP connection attempts concurrently within the
address group selected by `prefer` and uses the first success. Other attempts
are closed when a winner is selected, the dial times out or the Flow is cancelled. DNS
resolution and every attempt share the existing TCP dial timeout. Source address
binding and family restrictions apply to each candidate. A literal target IP
still produces a single attempt.

`prefer` takes precedence over concurrency. With `prefer=ipv4`, all eligible
IPv4 addresses race first; only after every IPv4 attempt fails do IPv6 addresses
race. `prefer=ipv6` reverses the groups. If the preferred family has no eligible
addresses, the other family starts immediately. A pending preferred attempt
continues until it fails or the shared dial timeout expires; timeout ends the
Flow without granting the fallback group another timeout.
With `prefer=default` (or omission), all eligible addresses race together.
Leave `tcp-concurrent=0` (the default) to try addresses sequentially in
preference order. UDP Flows, including SOCKS5 UDP associations, retain their
existing sequential setup.

For a SOCKS5 upstream, the race uses the proxy's resolved addresses and a
candidate succeeds after SOCKS authentication and CONNECT finish. Target domains
remain unchanged for remote resolution by the proxy. Business payload is sent
only through the winning connection.

```sh
nowhere "portal://KEY@*:2000?prefer=ipv6&tcp-concurrent=1"
```

A SOCKS5 upstream must support UDP ASSOCIATE to carry UDP Flows. Failure to
establish that association fails the affected Flow.

### SOCKS credentials

Portal's SOCKS5 `out` and Vector's `in` split credentials at raw delimiters
before decoding each component once. Percent-encode reserved credential
characters. For example:

```text
out=a%3Ab:p%40ss@127.0.0.1:1080
```

The decoded username is `a:b` and the password is `p@ss`. Both components must
contain between 1 and 255 UTF-8 bytes.

## Vector URL

```text
vector://KEY@ENDPOINT?in=[USER:PASS@]HOST:PORT
```

Vector connects to Portal over the carrier selected by `ENDPOINT`.

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `in` | `[USER:PASS@]HOST:PORT` | Required for a service; optional for probe | Local SOCKS5 listener, with optional authentication |
| `sni` | ASCII DNS name, empty or `none` | Endpoint host | Verified server name; empty or `none` uses the host |
| `pin` | 64 lowercase hexadecimal characters, empty or `none` | System CA and hostname verification | Exact certificate SHA-256; empty or `none` uses normal verification |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |
| `rate` | `0..=2147483647` Mbps | `0` | Vector-to-Target upload limit; `0` disables it |
| `etar` | `0..=2147483647` Mbps | `0` | Target-to-Vector download limit; `0` disables it |

Obtain a fingerprint with `nowhere fingerprint` and compare it through a trusted
channel before setting `pin`. See [certificate trust](security.md#certificate-trust).
Upload and download follow the Vector-to-Target business direction, regardless
of which transport peer establishes the connection.

### SOCKS5 ingress

Vector supports SOCKS5 CONNECT and UDP ASSOCIATE; BIND is unsupported. It drops
SOCKS UDP packets with a nonzero fragmentation field. A UDP association uses a
separate ephemeral UDP socket and remains tied to its TCP control connection.
The requested UDP source must be an unspecified IP or the TCP peer's IP; a
domain source constraint is unsupported. If the request does not specify a
port, the first accepted UDP packet selects the source port for that association.

Without `USER:PASS@`, the listener accepts unauthenticated SOCKS5 clients. SOCKS5
credentials and traffic on this application-to-Vector hop are not encrypted by
Nowhere. Bind to loopback or protect the listener and its UDP sockets with an
appropriate network boundary.

## Egress URL

```text
egress://KEY@ENDPOINT
```

Egress connects to Portal over its selected TLS or QUIC carrier and provides
target access. The `HOST:PORT` shorthand selects QUIC.

| Parameter | Accepted value | Default | Purpose |
|---|---|---|---|
| `sni` | ASCII DNS name, empty or `none` | Endpoint host | Verified server name; empty or `none` uses the host |
| `pin` | 64 lowercase hexadecimal characters, empty or `none` | System CA and hostname verification | Exact certificate SHA-256; empty or `none` uses normal verification |
| `dial` | IP literal or `auto` | `auto` | Target source binding; an IP restricts target connections to its address family |
| `dial4` | IPv4 literal or `auto` | `auto` | IPv4 target source binding |
| `dial6` | IPv6 literal or `auto` | `auto` | IPv6 target source binding; IPv4-mapped addresses are invalid |
| `morph` | `0` or `1` | `1` | Shared-key wire masking; peers must agree |
| `rate` | `0..=2147483647` Mbps | `0` | Vector-to-Target upload limit; `0` disables it |
| `etar` | `0..=2147483647` Mbps | `0` | Target-to-Vector download limit; `0` disables it |

Egress's `dial`, `dial4` and `dial6` follow the same mutual-exclusion and
explicit-bind rules as Portal. They bind outbound target sockets and filter
resolved target addresses. DNS lookup uses the host resolver; these options
do not select the DNS query's source address. Egress-to-Portal connections
use automatic source selection.

## Parsing configuration

Unknown parameters and their values are ignored. For recognized parameters,
the first duplicate wins; an invalid first value is an error.

| Query | Result |
|---|---|
| `morph=1&morph=0` | Morph is enabled |
| `morph=invalid&morph=1` | Configuration error |

Startup logs show role URLs with explicit defaults. Shared Key, SOCKS
credentials, `crt`, `key` and unknown options are omitted. Portal with
`out=egress` also omits source-binding parameters. These redacted URLs are
diagnostic views, not complete launch configurations.

## Built-in DNS

Portal and Egress can run an embedded, encrypted forwarding resolver. It is
disabled unless `dns` is configured. Once enabled, `dns-hijack=1` is the default:
**every authenticated TCP or UDP Flow targeting port 53 is answered by this
resolver**, regardless of the target IPv4 address, IPv6 address or domain name.
The original destination is never contacted or resolved. Vector requires no
change. Both TLS and QUIC carriers and both Morph modes support interception.

Interception runs before fixed-outlet selection, including a SOCKS5 upstream or
an offline Egress registry. Configure DNS on Portal to answer there, or configure
it on Egress to answer at the exit. If both are configured, Portal intercepts
first. This does not redirect traffic that bypasses Nowhere, intercept encrypted
client DNS (DoH/DoT/DoQ), install firewall rules, or open a public DNS listener.

| Parameter | Default | Meaning / bounds |
|---|---|---|
| `dns` | Disabled | Comma-separated primary encrypted upstream URLs; required with any DNS option |
| `dns-fallback` | Absent | Comma-separated fallback URLs; at most 8 upstreams total |
| `dns-hijack` | `1` | `1`: intercept TCP/UDP target port 53; `0`: retain normal forwarding |
| `dns-cache-size` | `4096` | Maximum cached entries, `1..=65536` |
| `dns-cache-bytes` | `8388608` | Maximum charged cache bytes, `1..=67108864` |
| `dns-stale` | `1h` | Maximum optimistic stale window after TTL expiry, `0s..=24h`; `0s` disables stale answers |
| `dns-timeout` | `2s` | Total per-query deadline shared by primary/fallback, `10ms..=30s` |
| `dns-fallback-delay` | `50ms` | Start the next candidate after this budget, `1ms..=2s`, less than `dns-timeout` |
| `dns-probe-interval` | `250ms` | Minimum delay after a health test before the next test, `10ms..=60s` |
| `dns-probe-target` | `.` | DNS health-test name: root uses NS; any other name uses A |

Upstreams use `https://HOST[:443]/dns-query` (DoH over HTTP/2),
`tls://HOST[:853]` (DoT), or `quic://HOST[:853]` (DoQ, RFC 9250). Certificates
must validate against the system trust store and match `HOST`. There is no
insecure mode or implicit plaintext fallback. Encrypted sessions are reused;
TCP sockets use TCP_NODELAY. Upstream requests connect directly from the resolver
host, obey its `dial`/`dial4`/`dial6` and address preference, and do not traverse
the fixed SOCKS5/Egress outlet.

An upstream URL may contain one `bootstrap=IP` parameter. It fixes the remote
IP while preserving the URL host for TLS identity verification. Otherwise,
hostname upstreams are bootstrapped using the host's system resolver. Use an IP
URL with a matching certificate or explicit bootstrap to avoid that plaintext
bootstrap lookup. No system-DNS retry occurs when encrypted resolution fails.
Percent-encode nested URL query delimiters inside a role URL:

```sh
nowhere 'portal://KEY@*:2000?prefer=ipv4&tcp-concurrent=1&dns=https://1.1.1.1/dns-query&dns-fallback=tls://1.0.0.1&dns-fallback-delay=50ms&dns-probe-interval=250ms'
nowhere 'portal://KEY@*:2000?dns=quic://dns.adguard-dns.com%3Fbootstrap%3D94.140.14.14&dns-fallback=https://1.1.1.1/dns-query'
```

Configured, healthy primary upstreams precede fallbacks. A transport failure,
SERVFAIL, REFUSED or invalid reply starts the next candidate immediately. A slow
candidate starts the next after `dns-fallback-delay`; the first valid answer wins
and pending attempts are cancelled. Degraded candidates follow healthy
alternatives and are retried only if those alternatives also stall or fail.
Business-query errors (including SERVFAIL, REFUSED, FORMERR and NOTIMP), slow
queries and total timeouts request a separate health test. They do not directly
mark the upstream degraded or recovered. Only a failed health test marks it
degraded, and only a successful test restores its original priority. NXDOMAIN
and NOERROR/NODATA remain valid answers for ordinary client queries and do not
trigger fallback solely because of those result codes.

Health tests query `dns-probe-target` directly through the upstream, bypassing
the resolver cache. The default `.` requests NS records; e.g.
`dns-probe-target=example.com` requests A records. A successful test requires
NOERROR and an answer of the requested type. NXDOMAIN, NODATA, other errors,
invalid responses and timeouts all fail the test. Choose a stable name with the
expected records: a problem with the test name itself also fails this check.
Concurrent suspicions are coalesced into a pending test. Healthy idle upstreams
are not continuously tested; a suspicion wakes their first test immediately,
then `dns-probe-interval` limits further tests. Degraded upstreams continue
testing until recovery. Probe budgets are bounded by
`min(dns-timeout, max(dns-probe-interval, dns-fallback-delay))`. Millisecond
settings are scheduling budgets, not a guarantee on network RTT or TLS/QUIC
handshake completion. The first query initializes probe workers. Health changes
are visible in `nowhere status` immediately, while logs are debounced: continuous
degradation for one second produces an alert (checked every 250ms), followed by
at most one reminder per 60 seconds. Recovery logs appear only for a degradation
that was logged. Brief flaps produce no health logs. Notices contain upstream
indices and elapsed time, not client queries or the health-test name. Logging
does not delay fallback, health tests or recovery.

Fresh cached records age their TTLs, including the HTTP `Age` of DoH responses.
Expired positive answers return immediately
with TTL 1 and AD cleared while one deduplicated background refresh runs. Failed
refreshes never extend the stale window; refresh retries are throttled by
`dns-probe-interval`. Negative answers require an SOA, use the smaller SOA TTL and
MINIMUM, and are never served stale. TTL 0 and failed/truncated replies are not
cached. Cookies, ECS and other EDNS options bypass caching. The wire cache has
both count and byte limits and skips individual responses larger than 16 KiB.
At most 128 upstream query jobs and 64 DNS ingress operations run concurrently;
each UDP Flow retains at most 16 completed replies. These limits bound memory on
small servers.

UDP replies obey the client's advertised payload size (512 bytes without EDNS,
capped at 4096); larger answers set TC for a TCP retry. TCP supports length
framing and repeated/pipelined queries. Unsupported zone transfers and signed
TSIG requests return NOTIMP. This is a forwarding resolver, not a local DNSSEC
validator: fresh answers retain the upstream's AD result and stale answers clear
it. Client transaction IDs and question casing are restored on all answers.

When enabled, the same resolver also resolves direct domain targets and locally
resolved SOCKS5 proxy/UDP-relay names. It does not consult `/etc/hosts` for these
targets. A SOCKS5 target domain is still passed unchanged to the proxy for remote
resolution. Without `dns`, all prior resolution and port-53 forwarding behavior
is retained. Startup diagnostics show `dns=encrypted` and `dns-hijack`; actual
upstream URLs are omitted.

`nowhere status` includes DNS counters, cache usage, per-upstream health, current
preferred upstream and the last upstream that actually supplied an answer. A
probe restoring the primary changes the preference without changing the last
winner. Cached replies leave the last winner unchanged. See
[DNS statistics](telemetry.md#dns-statistics) for counter definitions.

## Parameter overview

A dash means that the role does not recognize the parameter.

| Parameter | Accepted value | Default | Portal | Vector | Egress |
|---|---|---|:---:|:---:|:---:|
| `in` | `[USER:PASS@]HOST:PORT` | Required for Vector service | — | Yes | — |
| `out` | `direct`, `egress`, `[USER:PASS@]HOST:PORT` | `direct` | Yes | — | — |
| `tls` | `1`, `2` | `1` | Yes | — | — |
| `crt` | Certificate-chain PEM path | Absent | Yes | — | — |
| `key` | Private-key PEM path | Absent | Yes | — | — |
| `sni` | ASCII DNS name, empty, `none` | Endpoint host | — | Yes | Yes |
| `pin` | 64 lowercase hex characters, empty, `none` | System CA and hostname verification | — | Yes | Yes |
| `dial` | IP literal, `auto` | `auto` | Yes | — | Yes |
| `dial4` | IPv4 literal, `auto` | `auto` | Yes | — | Yes |
| `dial6` | IPv6 literal, `auto` | `auto` | Yes | — | Yes |
| `prefer` | `ipv4`, `ipv6`, `default` | `default` | Yes | — | — |
| `tcp-concurrent` | `0`, `1` | `0` | Yes | — | — |
| `morph` | `0`, `1` | `1` | Yes | Yes | Yes |
| `rate` | `0..=2147483647` Mbps | `0` | Yes | Yes | Yes |
| `etar` | `0..=2147483647` Mbps | `0` | Yes | Yes | Yes |
| `dns`, `dns-fallback` | Encrypted upstream URL list | Disabled / absent | Yes | — | Yes |
| `dns-hijack` | `0`, `1` | `1` with `dns` | Yes | — | Yes |
| DNS cache, timeout and failover options | See [Built-in DNS](#built-in-dns) | See above | Yes | — | Yes |

## Rate limits

Each role applies `rate` and `etar` to the aggregate business payload it
handles across its TCP and UDP Flows. Values are decimal megabits per second;
`0` disables the corresponding limit. Each service has its own limits, so a
Flow passing through Vector, Portal and Egress can encounter limits at each hop.
These limits do not account for transport headers, encryption or retransmissions.

## Runtime environment

Set environment variables before starting the service. Byte sizes use integer
values; duration settings use values such as `5s` or `250ms`. Vector, Portal and
Egress validate all duration settings listed below at startup, including settings
not used by the selected role or carrier. Values must be positive, valid Unicode,
and fit the duration parser and timer implementation; UDP idle must also fit
QUIC's idle-timeout limit. Invalid values fail startup with the variable name.
Only unset variables use defaults.

`NOW_QUIC_UDP_QUEUE_BYTES` is also validated once at startup by all three roles,
including TLS-only configurations. It accepts positive integer byte counts up to
the smaller of `Semaphore::MAX_PERMITS` and `u32::MAX`. The saved value bounds each
QUIC connection's UDP queue and reassembly reservations, and Vector's separate
local UDP queue budget. Invalid values fail startup with the variable name.
`NOW_TCP_DATA_BUF_SIZE` is likewise validated at startup by all three roles and
must be in `1..=isize::MAX`. `NOW_PORTAL_TLS_IDLE_MAX` is validated by Portal
and Egress, including configurations that do not use TLS Egress registrations.

| Variable | Default | Purpose |
|---|---|---|
| `NOW_TCP_DATA_BUF_SIZE` | `32768` | TCP copy buffer bytes |
| `NOW_TCP_DIAL_TIMEOUT`, `NOW_UDP_DIAL_TIMEOUT` | `15s` | Target dial limits |
| `NOW_HANDSHAKE_TIMEOUT` | Shared Key-derived `3s`–`30s` | Transport/authentication limit |
| `NOW_FLOW_SETUP_TIMEOUT` | `20s` | Complete Flow setup operation deadline |
| `NOW_TCP_READ_TIMEOUT` | `30s` | TCP half-close completion limit |
| `NOW_UDP_IDLE_TIMEOUT` | `120s` | UDP Flow/QUIC idle limit |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4194304` | Connection-wide queue/reassembly reservation |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Bounded drain |
| `NOW_RELOAD_INTERVAL` | `1h` | Minimum interval between supplied-certificate reload attempts |
| `NOW_SERVICE_COOLDOWN` | `3s` | Egress reconnect and failed-seed backoff |
| `NOW_EGRESS_TLS_POOL_MAX` | `128` | Maximum TLS Egress pending connections per process |
| `NOW_PORTAL_TLS_IDLE_MAX` | `128` | Portal-wide TLS Egress pending capacity |
| `NOW_TRANSPORT_MEMORY_PROFILE` | `throughput` | QUIC window profile |
| `NOW_MORPH_TCP_PRELUDE` | `fade` | [Morph TCP Prelude policy](#tcp-morph-prelude): `fade`, `full8` or `low7` |
| `NOW_MORPH_UDP_PRELUDE` | `fade` | [Morph UDP Prelude policy](#udp-morph-prelude): `fade`, `full8` or `low7` |

### Timeout semantics

When `NOW_HANDSHAKE_TIMEOUT` is unset, each instance derives its default once
from the URL-decoded, validated Shared Key bytes:

```text
digest = HMAC-SHA256(key = SharedKey, data = "nowhere/handshake-timeout")
value = BE64(digest[0..8])
timeout = (3000 + 100 * (value % 271)) ms
```

The key is used as ASCII bytes, without hexadecimal decoding. The label is the
exact ASCII string shown, with no suffix or NUL. The 271 possible values span
3.0–30.0 seconds in 100ms steps. For example, Shared Key
`0123456789abcdef0123456789abcdef` produces `9100ms`. The same key produces the
same default in Portal, Vector, Egress, Probe and certificate fingerprint queries,
regardless of TLS/QUIC or Morph. Instances with different keys are independent.

An explicit value takes precedence, must meet the duration validation above, and
may be outside the derived range. Services save the effective value at startup.
Connections, reconnects and Flows reuse that value. Vector's SOCKS5 handshake
and TLS UDP tunnel close also use the instance value. Flow setup has a separate
20s default deadline, which can expire before a longer handshake budget.

- **Operation Deadline:** one budget for an operation, without restarting it at
  each stage. Vector TCP and UDP setup share `NOW_FLOW_SETUP_TIMEOUT` from the
  start of setup through READY, including DNS, connection acquisition, initial
  TLS/QUIC handshakes, reuse/lock and Stream-credit waits, AuthFrame and request
  writes, and result reads. Handshake stage limits also apply within that budget.
  Portal-to-Egress setup keeps one budget for selection, claim, request and
  result. Probe uses the same Vector setup operation; cleanup has its own budget.
  QUIC Egress registration uses one `NOW_HANDSHAKE_TIMEOUT` after transport
  connection, covering `open_bi`, AuthFrame write/finish and the complete reply.
  `NOW_TCP_READ_TIMEOUT` is a completion deadline for the remaining TCP direction
  after the other direction finishes normally (Half-Close). Traffic does not
  restart it; it is not a timeout on every TCP read.
- **Idle Timeout:** `NOW_UDP_IDLE_TIMEOUT` controls UDP Flow activity and QUIC
  transport idle timeouts. It does not cap the total lifetime of an active
  Flow. Fully open TCP Flows have no read-idle timeout.
- **Fixed TTL:** unused TLS Egress standby connections expire after a fixed
  `120s`, independently at Portal and Egress. Activity does not renew this TTL;
  claimed connections leave standby and follow normal Flow lifetime rules.
  UDP fragment reassembly expires after `10s`.

Setup deadlines end at READY; they do not limit established Flow lifetimes.

### QUIC window profiles

| Profile | Stream receive | Connection receive | Send window |
|---|---:|---:|---:|
| `memory` | 4 MiB | 8 MiB | 8 MiB |
| `balanced` | 8 MiB | 16 MiB | 16 MiB |
| `throughput` | 16 MiB | 32 MiB | 32 MiB |

Portal uses a 64 KiB connection receive window before authentication and raises
it after success. Transport windows are separate from UDP application budgets
and do not represent total process memory.

### TCP Morph prelude

Morph TCP emits an [Authenticated Prelude](prelude.md). After
generating the base prelude, it replaces the last 32 bytes' low seven bits with
masked authentication data; the first 32 bytes and all highest bits retain the
selected policy.

`NOW_MORPH_TCP_PRELUDE` selects the base Prelude generation policy. The receiver
consumes the 64-byte prelude independently of that policy; this setting is not
negotiated and need not match the peer's generation policy.

The [Morph TCP Prelude specification](prelude.md#morph-tcp-prelude) defines
the three base generation policies, authentication encoding and acceptance.
TCP Fade uses randomized ASCII/low7/full8 boundaries; authentication
encoding preserves the base prefix and all highest bits.

### UDP Morph prelude

`NOW_MORPH_UDP_PRELUDE` selects `fade` (default), `full8` or `low7` for the
independent 12-byte Prelude sent once by each new Morph QUIC client socket.
Vector and Egress share this behavior. UDP Fade uses fixed 2B ASCII + 8B low7 +
2B full8 boundaries. See [Morph UDP Prelude](prelude.md#morph-udp-prelude) for
exact distributions, nonblocking send semantics and receiver compatibility.

Each variable is validated only for Morph clients using its corresponding
carrier. Values are case-sensitive; empty, unknown and non-Unicode values are
invalid. Portal and clients with `morph=0` do not use these policy variables.
Neither policy is negotiated or included in service or share URLs. With Morph
enabled, certificate inspection sends a TCP Prelude; when its share link selects
`net=udp`, parsing also validates the UDP policy.
