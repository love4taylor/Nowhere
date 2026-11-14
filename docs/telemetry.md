# Telemetry

Nowhere publishes cumulative logical traffic, active Flow counts and optional
built-in DNS statistics over protected local IPC. Service logs use stdout and stderr.

The contract identifier is `nowhere.telemetry`.
The JSON messages and [JSON Schema](#json-schema) below define the contract
for all roles.

## Contents

- [Discovery and identity](#discovery-and-identity)
- [Framing](#framing)
- [Messages](#messages)
- [Statistics](#statistics)
- [Delivery and ordering](#delivery-and-ordering)
- [Privacy and trust](#privacy-and-trust)
- [Resource limits](#resource-limits)
- [Containers](#containers)
- [Status](#status)
- [JSON Schema](#json-schema)

## Discovery and identity

Service and collector use the platform system temporary directory and the
same operating-system user. Each instance publishes one registry record at
startup; the record is not a periodically written log.

### Unix

The directory `nowhere-telemetry-<effective UID>/` is owned by that user with
mode `0700`. An instance atomically publishes
`nowhere.<32 lowercase hexadecimal instance ID>.json` with mode `0600`.

Its `endpoint` is a Unix socket in the same private directory. Socket filenames
are `<first 16 hexadecimal characters of the instance ID>.sock` to fit platform
path limits. The socket has mode `0600` and is not a data-storage file.

### Windows

The directory suffix is the first 16 bytes of SHA-256 of the current user's SID
string encoded as UTF-8, rendered as lowercase hexadecimal. Endpoints are local
byte-mode named pipes:

```text
\\.\pipe\nowhere-telemetry-<user suffix>-<instance ID>
```

Directories, files and pipes restrict access to that user. Remote pipe clients
are rejected. Windows `uid` is metadata only and is not an authorization ID.

### Validate discovery

| Registry field | Meaning |
|---|---|
| `protocol` | Contract identifier |
| `instance` | Registry name, UID, PID and process incarnation |
| `transport` | `unix_socket` or `named_pipe` |
| `endpoint` | Protected local IPC address |
| `namespace` | Process namespace identity |

Records contain no business address, configuration or traffic
history. Before trusting a record:

1. Check permissions, object type, endpoint namespace and peer identity.
2. Check that the filename matches the embedded instance identity.
3. On Linux, check namespace identity before PID checks or cleanup.
4. Check process liveness and validate its incarnation where the platform supports it.
5. Match Hello's contract, instance ID and PID against discovery after connecting.

Linux compares boot, PID namespace and user namespace identity and checks the
socket peer PID. Windows checks the named-pipe server PID and user identity.
macOS checks socket peer UID and registry/Hello identity; it does not compare
process start times to detect PID reuse.

A failed connection alone does not establish that a record is stale. Remove
records only after confirming process death or an incarnation mismatch.
Unavailable process identity is not evidence of death. Instance IDs change
at every start; discovery and cleanup stay within the namespace specified here.

### Startup and cleanup

Services remove their registry record and socket on normal exit. If permissions,
identity, entropy or path length cannot be guaranteed, local IPC initialization
fails closed and forwarding continues with an error on stderr. There is no fallback.

Hello includes an instance descriptor with role `portal`, `vector` or `egress`,
release version and endpoint.
See [Privacy and trust](#privacy-and-trust) for visible metadata.

## Framing

Every frame contains a four-byte unsigned big-endian payload length followed
by exactly that many UTF-8 JSON bytes. The length excludes its own prefix:

```text
+-------------------+---------------------------------------+
|   Length: u32 BE  |        UTF-8 JSON: length bytes       |
+-------------------+---------------------------------------+
```

Server JSON payloads are limited to 65536 bytes. Collectors send no data.

Read exactly the specified bytes; one read does not necessarily contain a
whole message. Zero lengths and invalid JSON are rejected. Preserve 64-bit
integer precision, for example with a lossless JSON parser rather than ordinary
JavaScript Number for counters and identifiers.

## Messages

The server sends `hello`, an immediate `snapshot`, then a `snapshot` every second.
Clients send no commands. Any input is read and discarded without parsing;
EOF or an I/O error closes the connection and releases its connection slot.
An idle read-only client remains connected. Reconnection begins with a new Hello
and the latest statistics.

Hello contains `instance`: `contract`, random `id`, `role`, `pid`,
`version` and validated `endpoint`. Identity checks precede trusting statistics.

```json
{
  "type": "hello",
  "data": {
    "instance": {
      "contract": "nowhere.telemetry",
      "id": "0123456789abcdef0123456789abcdef",
      "role": "portal",
      "pid": 42,
      "version": "dev",
      "endpoint": "127.0.0.1:2000"
    }
  }
}
```

Snapshot always contains six traffic integer fields. A Portal/Egress with the
built-in resolver also includes the optional `dns` object:

| Field | Meaning |
|---|---|
| `tcp_upload_bytes` | Cumulative TCP payload toward the target |
| `tcp_download_bytes` | Cumulative TCP payload toward the Vector |
| `udp_upload_bytes` | Cumulative UDP payload toward the target |
| `udp_download_bytes` | Cumulative UDP payload toward the Vector |
| `tcp_active` | Currently owned TCP business Flows |
| `udp_active` | Currently owned UDP business Flows |
| `dns` | Resolver counters and upstream health; omitted when DNS is disabled |

```json
{
  "type": "snapshot",
  "data": {
    "tcp_upload_bytes": 12345,
    "tcp_download_bytes": 67890,
    "udp_upload_bytes": 512,
    "udp_download_bytes": 1024,
    "tcp_active": 2,
    "udp_active": 1,
    "dns": {
      "hijack": true,
      "queries": 100,
      "cache_hits": 60,
      "stale_hits": 10,
      "cache_misses": 30,
      "deduplicated": 5,
      "refreshes": 3,
      "failures": 1,
      "fallback_replies": 4,
      "upstream_switches": 2,
      "tcp_queries": 20,
      "udp_queries": 76,
      "cache_entries": 25,
      "cache_bytes": 16384,
      "in_flight": 0,
      "preferred_upstream": 0,
      "last_upstream": 1,
      "upstreams": [
        {
          "endpoint": "https://dns.example:443",
          "fallback": false,
          "healthy": true,
          "queries": 25,
          "failures": 1,
          "probes": 2,
          "last_latency_us": 2000
        },
        {
          "endpoint": "tls://1.1.1.1:853",
          "fallback": true,
          "healthy": true,
          "queries": 4,
          "failures": 0,
          "probes": 0,
          "last_latency_us": 3000
        }
      ]
    }
  }
}
```

## Statistics

Upload follows Vector → Portal → optional Egress → Target. Download follows
the reverse direction. Protocol framing, authentication, Morph, encryption,
QUIC control traffic and retransmissions do not contribute to logical payload
counters. A UDP association may own several target Flows. A target Flow becomes
active after setup; its owner releases the count on completion or cancellation.

Counters accumulate from process startup even without IPC clients. Each process
accounts for its own work. Adding Portal, Vector and Egress totals does not yield
unique end-to-end traffic. Preserve unsigned 64-bit precision in consumers.
Counters and active counts are independent atomic reads, not a transactional
multi-field sample. Active counts are nonnegative in normal ownership operation.

Nowhere does not persist counters; they reset when the process restarts.
Reconnecting to the same process replaces its latest values and must not add
the sample twice. A new instance ID identifies a new process lifetime.

### DNS statistics

| Field inside `dns` | Meaning |
|---|---|
| `hijack` | Whether TCP/UDP target port 53 is intercepted |
| `queries`, `failures` | Logical resolution calls and calls that return an error; includes locally resolved A/AAAA questions, excludes rejected malformed/unsupported packets |
| `cache_hits`, `stale_hits`, `cache_misses` | Fresh hits, optimistic stale hits, and calls without a usable cache answer; EDNS bypasses count as misses |
| `deduplicated` | Calls joining an existing upstream job instead of starting another |
| `refreshes` | Background stale-refresh jobs actually started |
| `fallback_replies` | Upstream jobs won by a configured fallback, including background refreshes |
| `upstream_switches` | Changes of the winning upstream index after the first winner |
| `tcp_queries`, `udp_queries` | Intercepted DNS packets by transport, including rejected packets; excludes internal domain lookups |
| `cache_entries`, `cache_bytes` | Retained cache entries and charged bytes; includes expired entries awaiting lazy removal/eviction |
| `in_flight` | Currently owned upstream jobs, including background refreshes |
| `preferred_upstream` | Zero-based index of the first non-degraded upstream; `null` if all are degraded |
| `last_upstream` | Zero-based index of the last upstream job winner; `null` before any successful answer |
| `upstreams` | At most eight configured upstreams, primary first, then fallback |

Each upstream reports `endpoint` (scheme, host and port only), `fallback`,
`healthy`, `queries`, `failures`, `probes` and `last_latency_us`. Query counts
include attempts cancelled after another upstream wins; cancellations are not
failures. Failed attempts and attempts unfinished at the total query deadline
count as failures. Probes have a separate count and never replace the last
winner or last successful non-probe query latency. `healthy` reflects the last
health-test decision: only the configured `dns-probe-target` can mark an upstream
degraded or recovered. Ordinary query errors/latency only request a health test.
A newly configured upstream has not necessarily been contacted. Health logs are
debounced independently; status does not wait for the one-second log threshold.

Cache hits do not change the winning upstream. A recovery probe can restore
the preferred upstream before another real query uses it. Therefore current
preference and last actual use are separate fields; simultaneous queries may
be using several upstreams. Reading a snapshot never starts a query, refresh
or probe. The new collector accepts older six-field snapshots. Collectors that
reject unknown fields must be upgraded to read snapshots containing `dns`.

## Delivery and ordering

A connection delivers ordered snapshots of current statistics; there is no event
history, replay, sequence number, sampler timestamp or log message.
The consumer records receive time and derives throughput from differences.
Active counts may lag by approximately one second.

Writing one frame has a five-second limit. Clients should connect and read complete
messages with a five-second deadline. On timeout or disconnection, reconnect
and validate a new Hello before reading the latest Snapshot. Active counts are
stale until a new Snapshot arrives. IPC availability does not establish process
state.

## Privacy and trust

IPC requires the local user, platform permissions, process identity and namespace
checks described above. Hello excludes credentials; its endpoint is validated.
IPC contains no queried names, target addresses, client addresses or errors.
DNS metadata includes upstream scheme, host and port; it excludes custom DoH
paths, credentials, bootstrap addresses, query parameters and fragments.

Service stdout contains startup configuration without credentials, TLS
fingerprints and graceful shutdown information. Service stderr contains original
exception details and their cause chains; addresses and file paths may appear.
Errors are constructed without passwords, Shared Keys or complete credential
URLs. Logs use `2026-10-11T08:30:00.123Z message`, without levels or ANSI colors.
Original error chains retain their text, casing and any addresses. Embedded
newlines are escaped so each log record occupies one line.

Normal Flow starts, successful finishes, normal EOF, active cancellation and
ordinary UDP idle cleanup produce no access logs.

## Resource limits

There are at most 16 IPC connections. Frames are at most 64 KiB and each write
has a five-second timeout. Input is discarded through a fixed-size buffer.
Slow readers, EOF and I/O errors release connection resources. Snapshots use a
fixed one-second interval without an event queue.

## Containers

The publisher and consumer share the same user, temporary directory, container
and process/network namespaces. Permissions and peer validation remain enabled.
Host-to-container and cross-container observation are outside the contract.

## Status

`nowhere status` reads Hello and the first Snapshot with a two-second per-instance
deadline. It displays role, PID, instance ID, endpoint and the six traffic statistics.
When the publisher includes `dns`, it also displays current preferred and last-used
upstreams, hijacking, query/error totals, cache hits/rate/storage, refresh and
deduplication totals, fallback replies/switches, active jobs, and per-upstream
health, attempts, errors, probes and last successful query latency. An older or
DNS-disabled publisher has no DNS rows.
Service process state is the supervisor's responsibility.

## JSON Schema

This Draft 2020-12 schema validates the JSON payload inside each frame.
It can be copied directly into a JSON Schema validator.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:nowhere:telemetry",
  "title": "Nowhere Telemetry",
  "oneOf": [
    {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type",
        "data"
      ],
      "properties": {
        "type": {
          "const": "hello"
        },
        "data": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "instance"
          ],
          "properties": {
            "instance": {
              "type": "object",
              "additionalProperties": false,
              "required": [
                "contract",
                "id",
                "role",
                "pid",
                "version",
                "endpoint"
              ],
              "properties": {
                "contract": {
                  "const": "nowhere.telemetry"
                },
                "id": {
                  "type": "string",
                  "pattern": "^[0-9a-f]{32}$"
                },
                "role": {
                  "enum": [
                    "portal",
                    "vector",
                    "egress"
                  ]
                },
                "pid": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 4294967295
                },
                "version": {
                  "type": "string"
                },
                "endpoint": {
                  "type": "string"
                }
              }
            }
          }
        }
      }
    },
    {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type",
        "data"
      ],
      "properties": {
        "type": {
          "const": "snapshot"
        },
        "data": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "tcp_upload_bytes",
            "tcp_download_bytes",
            "udp_upload_bytes",
            "udp_download_bytes",
            "tcp_active",
            "udp_active"
          ],
          "properties": {
            "tcp_upload_bytes": {
              "type": "integer",
              "minimum": 0,
              "maximum": 18446744073709551615
            },
            "tcp_download_bytes": {
              "type": "integer",
              "minimum": 0,
              "maximum": 18446744073709551615
            },
            "udp_upload_bytes": {
              "type": "integer",
              "minimum": 0,
              "maximum": 18446744073709551615
            },
            "udp_download_bytes": {
              "type": "integer",
              "minimum": 0,
              "maximum": 18446744073709551615
            },
            "tcp_active": {
              "type": "integer",
              "minimum": 0,
              "maximum": 9223372036854775807
            },
            "udp_active": {
              "type": "integer",
              "minimum": 0,
              "maximum": 9223372036854775807
            },
            "dns": {
              "$ref": "#/$defs/dns"
            }
          }
        }
      }
    }
  ],
  "$defs": {
    "dns": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "hijack",
        "queries",
        "cache_hits",
        "stale_hits",
        "cache_misses",
        "deduplicated",
        "refreshes",
        "failures",
        "fallback_replies",
        "upstream_switches",
        "tcp_queries",
        "udp_queries",
        "cache_entries",
        "cache_bytes",
        "in_flight",
        "preferred_upstream",
        "last_upstream",
        "upstreams"
      ],
      "properties": {
        "hijack": {
          "type": "boolean"
        },
        "queries": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "cache_hits": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "stale_hits": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "cache_misses": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "deduplicated": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "refreshes": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "failures": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "fallback_replies": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "upstream_switches": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "tcp_queries": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "udp_queries": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "cache_entries": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "cache_bytes": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "in_flight": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "preferred_upstream": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 0,
          "maximum": 7
        },
        "last_upstream": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 0,
          "maximum": 7
        },
        "upstreams": {
          "type": "array",
          "maxItems": 8,
          "items": {
            "$ref": "#/$defs/dns_upstream"
          }
        }
      }
    },
    "dns_upstream": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "endpoint",
        "fallback",
        "healthy",
        "queries",
        "failures",
        "probes",
        "last_latency_us"
      ],
      "properties": {
        "endpoint": {
          "type": "string",
          "maxLength": 512
        },
        "fallback": {
          "type": "boolean"
        },
        "healthy": {
          "type": "boolean"
        },
        "queries": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "failures": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "probes": {
          "type": "integer",
          "minimum": 0,
          "maximum": 18446744073709551615
        },
        "last_latency_us": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 0,
          "maximum": 18446744073709551615
        }
      }
    }
  }
}
```
