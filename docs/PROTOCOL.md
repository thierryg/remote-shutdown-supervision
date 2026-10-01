<!--
=============================================================================
Remote Shutdown - LAN parental control and machine management (master/agent)
=============================================================================
File    : docs/PROTOCOL.md
Purpose : Reference of the discovery, enrollment and agent protocols (every message)
Author  : Thierry Gayet <thierry.gayet@labworks.fr>
Project : remote-shutdown (version: VERSION)
Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
=============================================================================
-->
# Protocol reference (version 1)

Three channels, each with one job:

| Channel | Transport | Authentication | Used for |
|---|---|---|---|
| Discovery | UDP 50000, broadcast + unicast answer | none (hint only) | finding the master |
| Enrollment | HTTPS 8443, `POST /api/enroll` | one-time token + pinned CA fingerprint | obtaining a client certificate |
| Agent link | TCP 8444, TLS 1.2+ with client certificate, JSON lines | mutual TLS | everything else |

Broadcast is never used for commands.

## 1. Discovery

Agent → `255.255.255.255:50000` and every directed broadcast address:

```json
{"type": "DISCOVER", "version": "0.1.0"}
```

Master → agent (unicast; at most one answer per source address and second):

```json
{"type": "MASTER", "version": "0.1.0", "web_port": 8443, "agent_port": 8444,
 "ca_fingerprint": "9aa55f2f…526a"}
```

The agent takes the master address from the source of the datagram. The answer is not
trusted: enrollment pins the fingerprint given out of band, and every later connection
verifies the chain against the stored CA.

## 2. Enrollment

```
POST https://<master>:8443/api/enroll
{"token": "<one-time token>", "csr": "-----BEGIN CERTIFICATE REQUEST-----…", "hostname": "kid-pc"}
```

1. The agent generates an ECDSA P-256 key locally (it never leaves the machine) and a CSR.
2. TLS: the agent accepts the server only if the chain contains a CA whose SHA-256
   fingerprint equals `--fingerprint`, and the leaf has the serverAuth usage.
3. The master atomically consumes one use of the token (SHA-256 lookup, expiry checked),
   chooses a UUID, and signs a certificate `CN=<uuid>, O=rsd-agent`, clientAuth only, 365 days.
   Only the public key of the CSR is used.
4. Answer `200`: `{"agent_id", "cert", "ca", "agent_port"}`. The agent checks that the CA has the
   pinned fingerprint and that the certificate is signed by it, then stores `client.key`
   (0600), `client.crt`, `ca.crt` and `state.json`.

Errors: `400 error.bad_request|error.bad_csr`, `403 error.invalid_token`,
`429 error.too_many_attempts` (10 failures per IP and 10 minutes).

## 3. Agent link

TLS with the client certificate; the agent verifies the master by chain and serverAuth EKU
(not by host name). The master identifies the agent by the certificate CN and refuses it when
the agent is unknown or the serial differs from the recorded one (deleted or superseded):

```json
{"type": "ERROR", "error": "certificate not accepted", "fatal": true}
```

Framing: one JSON object per line, UTF-8, `\n` terminated, at most 64 KiB. Unknown fields are
ignored; unknown types are logged and ignored. Every master command carries a `ref`.

### 3.1 Agent → master

| Type | Fields | When |
|---|---|---|
| `DECLARE` | `hostname`, `os`, `arch`, `version`, `boot_time` (Unix s), `interfaces` | right after connecting |
| `UPDATE` | `interfaces` | an interface or address changed (checked every 30 s) |
| `KEEPALIVE` | `timestamp`, `uptime` (s since boot or last resume) | every `keepalive_interval` (10 s) |
| `STATE` | `shutdown_at` (Unix s or `null`) | a shutdown was scheduled, cancelled or failed; after DECLARE |
| `ACK` | `ref`, `ok`, `error` | after each command |
| `CHAT` | `text`, `user` | the local user answered a chat message |
| `RENEW` | `csr` | the certificate expires within 30 days |

`interfaces` is a list of `{"name": "eth0", "ipv4": ["192.168.1.20"], "ipv6": ["fd00::20"],
"mac": "aa:bb:cc:dd:ee:ff"}` (up, non-loopback interfaces; link-local addresses omitted).

### 3.2 Master → agent

| Type | Fields | Agent behavior |
|---|---|---|
| `WELCOME` | `agent_id`, `protocol`, `server_time`, `keepalive_interval` | starts the keepalive and interface timers |
| `PONG` | `ref` | answer to each KEEPALIVE (lets the agent detect a dead link) |
| `SHUTDOWN` | `ref`, `delay` (s), `message`, `force`, optional `key` + `params` | shows the message, starts a countdown (replaces a pending one), powers off |
| `CANCEL_SHUTDOWN` | `ref` | stops the countdown, shows "cancelled" |
| `MESSAGE` | `ref`, `title`, `text`, optional `key` + `params` | popup on every graphical session |
| `CHAT` | `ref`, `text`, `author` | dialog with a reply field (Linux, macOS); message only on Windows |
| `RENEWED` | `cert`, `ca` | stores the certificate with the key of the RENEW, reconnects |
| `ERROR` | `error`, `fatal` | logged; `fatal` → the agent waits 5 minutes before retrying |

The countdown runs on the agent and survives a loss of the master connection: once ordered, a
shutdown can only be cancelled by the master.

**Localization.** Texts generated by the master carry an i18n `key` and its `params`
(`shutdown.default` {seconds}, `policy.warning` {minutes}, `policy.shutdown` {seconds}) next to
the English `text`/`message`. The agent renders the key in the language of each desktop user
(`agent/i18n/*.json`, 12 locales) and falls back to the English text for an unknown key. Free
text typed by the administrator has no key and is shown as is; window titles and buttons are
always localized.

### 3.3 Liveness

* An agent is **UP** while its connection is open and a line arrived less than
  `keepalive_timeout` (35 s) ago; the master closes silent connections.
* The agent sets a read deadline of 3 × keepalive + 5 s; without PONG it reconnects with an
  exponential backoff (1 s → 60 s, jitter) and, after 3 failures without a configured master,
  runs the discovery again.

## 4. Example session

```
agent  → {"type":"DECLARE","hostname":"kid-pc","os":"Ubuntu 24.04.1 LTS","arch":"amd64","version":"0.1.0","boot_time":1790860000,"interfaces":[…]}
master → {"type":"WELCOME","agent_id":"a909bfdd-…","protocol":1,"server_time":1790863500.1,"keepalive_interval":10}
agent  → {"type":"STATE","shutdown_at":null}
agent  → {"type":"KEEPALIVE","timestamp":1790863510,"uptime":3510}
master → {"type":"PONG","ref":"5f0c…"}
master → {"type":"SHUTDOWN","delay":60,"message":"Bedtime!","force":false,"ref":"17fc…"}
agent  → {"type":"STATE","shutdown_at":1790863575}
agent  → {"type":"ACK","ref":"17fc…","ok":true}
```
