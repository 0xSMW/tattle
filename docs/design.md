# tattle — design

Security monitoring for one person who runs a handful of laptops and servers and
has no SOC. Free to run. Assumes every machine will eventually be compromised, and
optimises for two things: knowing quickly, and limiting what one compromised
machine can reach.

## Principles

1. **Detection lives off the box.** Anything a compromised machine can edit, it
   can lie about. Reports leave the machine the moment they are made, into storage
   the machine can write to but never read, overwrite or delete.
2. **Silence is a signal.** A machine that stops reporting raises an alert. The
   check runs somewhere other than your own machines.
3. **Canaries before scanners.** A fake credential that nobody legitimate uses
   gives an alert with almost no false positives. Scanners find drift; canaries
   find intruders.
4. **No AI on the monitored machine, and no power for the AI that reads.**
   Collection is plain shell. The model that summarises reports gets read-only file
   access to copies of them, with no shell, network or credentials, because every
   byte it reads may have been written by an attacker.
5. **Free.** Cloudflare free tier, ntfy.sh, canarytokens.org, open-source
   collectors.

## Components

```
 machine (macOS / Linux)                Cloudflare (free)              you
 ┌──────────────────────┐   POST     ┌──────────────────────┐
 │ collector (launchd / │──────────▶ │ Worker: /ingest       │
 │ systemd timer, daily)│ per-host   │  write-once to R2     │
 └──────────────────────┘  token     │  (bucket lock 90d)    │
                                     │ cron: missed check-in │──▶ ntfy ──▶ phone
 canarytokens.org ── trip ──────────────────────────────────────▶ ntfy + email
                                     └──────────┬───────────┘
                                                │ read-only token
                                     ┌──────────▼───────────┐
                                     │ analyzer (scheduler)  │
                                     │  daily: deterministic │──▶ ntfy (only on
                                     │   diff, alert on bad  │    high-signal)
                                     │  weekly: LLM digest,  │──▶ digest
                                     │   read-only tools     │
                                     └──────────────────────┘
```

### collector

One POSIX shell script per OS. No dependencies beyond the base system (optionally
`lynis` and `osqueryi` when present). Produces one JSON document per run with fixed
sections:

| section | macOS | Linux |
|---|---|---|
| identity | hostname, serial, OS version | hostname, machine-id, OS, kernel |
| accounts | admin group members, users with UID ≥ 500 | sudo/wheel members, UID ≥ 1000, UID 0 accounts |
| ssh | authorized_keys fingerprints per user, sshd config hash | same |
| listening | listening TCP/UDP sockets with process | same |
| persistence | LaunchAgents/Daemons (paths + hashes), login items, cron, profiles | systemd units enabled, cron, rc.local, /etc/ld.so.preload |
| posture | FileVault, SIP, Gatekeeper, firewall, auto-updates | ufw/nftables summary, unattended-upgrades, pending security updates |
| packages | brew list, /Applications bundle IDs + versions | dpkg/rpm list hash + count |
| tailscale | `tailscale status --json` self + peers (names only) | same |
| lynis | — | hardening index + warnings (weekly) |

The collector never sends file contents beyond what is listed, and never sends
secrets. The ingest token is the only credential on the machine.

### worker (Cloudflare Worker + R2)

- `POST /ingest` with `Authorization: Bearer <host token>`. Tokens are stored as
  SHA-256 hashes mapped to a host name; a token can only write as its own host.
- Writes `reports/<host>/<ISO timestamp>.json`. Never overwrites, never deletes,
  exposes no read endpoint. R2 bucket lock retention (90 days) backs this up at the
  storage layer.
- Records `lastSeen/<host>` in KV.
- Cron trigger (hourly): any host past its expected interval (default 36h) raises
  one ntfy alert, then one reminder per day until it reports again.
- `POST /canary` webhook target for canarytokens.org, forwarding to ntfy at max
  priority. (Canary emails go to you directly as a second channel.)

### analyzer

Runs on any scheduler you have (cron, launchd, a CI schedule, an agent
platform's automation). Holds a read-only R2 token, no other credentials.

- **daily (deterministic):** for each host, diff the newest report against the
  previous one. Alert via ntfy on: new admin/sudo/UID-0 account, new SSH key, new
  persistence item, new listening port, posture regression (FileVault off,
  firewall off, SIP off, auto-updates off). Everything else goes into the weekly
  digest only.
- **weekly (LLM):** copy the week's reports and diffs into a scratch directory,
  run a model with read-only file tools over it, and produce a short digest: what
  changed, what looks wrong, what to fix first. Output is a summary for a human,
  never an action.

### canaries

A setup script that, given canarytokens.org tokens, plants per machine:

- a fake AWS profile appended to `~/.aws/credentials` under a plausible name
  (never `default`, never replacing real profiles)
- a fake `.env` in a likely repo directory
- a fake private SSH key with a DNS-token comment
- a "passwords" document token in the home directory

Each token's memo records host and location so an alert says exactly which machine
and which file was touched.

## Hardening baseline (documented, not automated)

Per machine type, the short list that most reduces blast radius: full-disk
encryption, auto-updates, non-admin daily accounts, SSH only over Tailscale,
no long-lived cloud keys on laptops, one credential per machine, backups that the
backed-up machine cannot delete.

## Repo split

- `tattle` (this repo, public): engine. No hostnames, tokens or findings.
- a private deployment repo per operator: host list, token hashes, ntfy topic,
  findings and audit notes.
