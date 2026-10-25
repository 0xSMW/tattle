# Hardening checklist

The short list that most reduces blast radius for a small fleet. Each item came
from a real audit. tattle reports on most of these but does not change them.

## Monitoring must not share credentials with what it monitors

- Deploy the tattle worker in a Cloudflare account used for nothing else, with
  credentials kept off every monitored machine. A laptop logged into the same
  account with `wrangler` can delete the worker and silence every alert.
- Add an outside dead-man's switch (for example a free healthchecks.io check)
  and set it as `HEARTBEAT_URL`. If the worker is deleted, that check alerts.
- Run the weekly analyzer somewhere that is not your most-privileged machine.

## Laptops

- **FileVault on.** `fdesetup status` is the source of truth. Apple-silicon
  "encrypted at rest" is not tied to your password and does not protect a stolen
  machine.
- **Updates actually installing.** A failed update can sit unnoticed for years.
  Check that the installed version is not behind an available one.
- **Passphrases on SSH keys**, or keys in the Secure Enclave or 1Password's SSH
  agent. A key file with no passphrase is a password written on the disk.
- **No long-lived cloud admin keys on disk.** Use SSO / short sessions. An old IAM
  user key with IAMFullAccess lets whoever holds it mint their own admin.
- **Credential files mode 600.**
- **Nothing served to the tailnet without auth.** `tailscale serve` exposes a port
  to every device on the tailnet, including servers that may be compromised.
- **App firewall:** review the allowed-incoming list (it can quietly include `nc`,
  `node`, or a tunnel binary).

## Servers

- SSH only over Tailscale. No public port 22.
- `docker`, `lxd` and `libvirt` group membership is root without a password. Treat
  them as admin groups.
- Docker-published ports bypass ufw/firewalld. Bind to 127.0.0.1 or the tailnet
  IP, never 0.0.0.0, unless the port is meant to be public.
- Behind Cloudflare: allow 80/443 only from Cloudflare's IP ranges, or anyone who
  finds the origin IP bypasses the WAF.
- A GitHub self-hosted runner on a production box means anyone who can push a
  workflow can run code there. Restrict runner groups to specific workflows.
- No plaintext passwords in `~/.ssh/config` comments.

## Trust between machines

- Map which machine's key logs into which (tattle collects `own-key` and
  `authorized_keys` fingerprints for this). Trust should flow from your laptop to
  servers, never from a server back to your laptop.
- Tailscale: tag servers, and write ACLs so tagged servers cannot reach personal
  devices. Turn on Tailnet Lock. Remove nodes offline for more than 14 days.

## Backups

- The machine being backed up must not be able to delete its backups. Use an
  append-only restic server, or an object-lock bucket with a write-only token, and
  run `forget --prune` from somewhere else.

## Accounts

- Require 2FA in every GitHub org you administer (check the member list first:
  members without 2FA are removed).
- Fine-grained, expiring tokens. A `gh` token with `workflow` scope can rewrite CI
  in every repo it reaches.
- Sweep public DNS (zone files plus certificate transparency on crt.sh) for
  forgotten hosts and records that point at IPs you no longer own.
