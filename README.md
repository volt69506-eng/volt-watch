# volt-watch

Read-only health and safety auditor for a **Tailscale-managed Linux host**.

It answers one question: *is this machine reachable, patched, and safe, and
will it come back by itself after a power cut?* It reads systemd, the
Tailscale mesh, the host firewall, sshd's own authentication settings, the
account database and the volatile power-restore register on Intel Macs, then
reports findings with a remedy for each. It never changes system state.

```console
$ volt-watch
$ echo $?
0
```

## Why this exists

A machine you reach over a mesh VPN has a specific set of ways to become
unreachable or exposed:

- **SSH open to the world** instead of only to the tailnet — the single most
  common way a home server gets compromised.
- **Tailscale logged out** — the node silently drops off the tailnet and every
  remote session dies with it.
- **Auto power-on disabled** — on Intel Macs the "power on when AC returns"
  bit lives in a chipset register the firmware clears on every power cycle, so
  a machine that loses power stays dark until someone presses the button.
- **A boot unit that should rewrite that register but isn't enabled** — the
  register is volatile, so the fix only holds if something reapplies it.

Each of these is invisible from the desktop and obvious in hindsight.

## Install

```bash
pip install volt-watch          # or: pipx install volt-watch
```

## Development & CI

Tests run in GitHub Actions on Python 3.10-3.14 (`.github/workflows/ci.yml`) for pushes and pull requests.

```bash
python -m pip install --upgrade pip pytest
python -m pip install -e .
python -m pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for TDD expectations and security reporting guidance.


Needs Python 3.10+. Reads `tailscale`, `ufw`, `setpci` and `systemctl` from the
host; a missing tool is treated as "not applicable" rather than as an error.

## Usage

```console
$ volt-watch                     # plain report
$ volt-watch --json              # machine-readable
$ volt-watch --quiet             # no output; exit code only
$ volt-watch; echo $?            # 0 = clean, 1 = warnings or worse

$ volt-watch --output /var/lib/volt-watch/last.json
$ volt-watch --since /var/lib/volt-watch/last.json
$ volt-watch --check power       # only the power.* checks
$ volt-watch --list-checks       # list check groups, prefixes, and finding names
$ volt-watch --fail-on critical  # exit 1 only for critical findings
```

Exit codes: `0` clean at the selected threshold, `1` at least one finding at or
above it, `2` an auditor or usage error. The default threshold is `warning`, so
`info` findings do not change the exit code. `--fail-on` takes `critical`,
`warning` or `info`: use `critical` to gate CI on serious findings only, or
`info` during a hardening push. An invalid value exits 2. **A degraded audit
always exits 1**, whatever the threshold — an incomplete report is never green.

`--output` writes the same JSON `--json` prints, so the next run can read it.
`--since` compares against it: a finding that is new or got worse exits 1, one
that cleared up exits 0. With `--since`, `--fail-on` applies to the new or
worsened findings; an explicit threshold is needed because the default there is
"any regression" (including `info`) for backwards compatibility. The comparison
uses the check and its evidence, not the message text. A missing baseline adds
an `auditor.no_baseline` `info` finding.

`--check PREFIX` runs only the checks whose name starts with the prefix, so
`--check power` runs every `power.*` check and nothing else. Repeat the flag or
use commas to select several groups (`--check security,network` or
`--check security --check network`). Overlapping prefixes never run a group
twice. An unknown prefix exits 2 and lists the available ones.

The JSON payload is versioned (currently `2`) and carries the `host` name, the
UTC `generated_at` timestamp and a `coverage` summary (`readers` attempted and
`degraded` reader names). `findings` and `counts` keep their shape, and
`--output` writes the same wrapper, so a `--since` baseline is versioned too.

An `auditor.degraded` finding includes `evidence.errors`, a list of records
with `reader`, `reason` and `kind`. The kinds are `timeout`, `missing_tool`,
`permission`, `command_failed` and `unknown`; timeout reasons include the
reader's time budget. `evidence.readers` remains a reader-to-reason map.
Neither field includes command output or exception text.

A v1 baseline (which has only `version`, `host`, `findings` and `counts`) stays
readable: `--since` compares findings only, so new provenance fields cannot
change the exit code against an older report. A v1 report copied as a baseline
still works exactly as before.

## Automation

Both machine-readable formats are stable enough to build on. `--format json`
prints one document, identical to `--json`; `--format ndjson` prints a meta
line (`version`, `generated_at`, `host`, `coverage`, `counts`) followed by one
line per finding. Neither contains ANSI codes.

```console
# list the checks that need attention
$ volt-watch --format json | jq -r '.findings[] | "\(.severity) \(.check)"'

# fail CI only on critical findings, keeping the human report for the log
$ volt-watch --fail-on critical; echo $?

# stream findings one at a time (meta first)
$ volt-watch --format ndjson | while IFS= read -r line; do echo "$line" | jq -c .; done
```

`--output` always writes the JSON baseline (never NDJSON), so it can be fed
back to `--since` regardless of the display format. Exit codes are described
above; a degraded audit exits 1 even with `--fail-on critical`.

## Checks

| Check | Severity | Meaning |
|---|---|---|
| `sshd.exposed` | critical | Port 22 is allowed on every interface, including the public one |
| `sshd.unrestricted` | warning | Nothing restricts port 22 and the firewall default allows incoming |
| `sshd.firewall_unreadable` | warning | The firewall could not be read, so SSH exposure is unknown |
| `sshd.root_login` | critical | sshd accepts a root login |
| `sshd.password_auth` | warning | sshd accepts password authentication |
| `security.empty_password_accounts` | critical | An account has an empty password field, so it can log in with no password |
| `security.shadow_unreadable` | warning | `/etc/shadow` could not be read, so passwordless accounts are unknown |
| `security.uid0_account` | critical | An account besides `root` and standard non-login placeholders (`sync`/`shutdown`/`halt` with their own shell) has UID 0 |
| `security.passwd_unreadable` | warning | `/etc/passwd` could not be read, so UID 0 accounts are unknown |
| `auditor.degraded` | warning | Some readers could not run, so the report is incomplete |
| `tailscale.exposed` | critical | A port is published to the internet with `tailscale funnel`, bypassing the firewall |
| `tailscale.ssh_enabled` | info | Tailscale SSH is enabled on this node (visible posture signal) |
| `tailscale.published` | info | A port is published to the tailnet with `tailscale serve` |
| `tailscale.backend` | critical | Backend state is `NeedsLogin`, `Stopped`, `NoState` or `Starting` |
| `network.listener_exposed` | critical | A wildcard-bound port has a firewall allow on every interface from a non-private source, so the default-deny policy is not what protects it |
| `network.listener_wide_bind` | info / warning | A non-SSH service listens on 0.0.0.0/::; warning when firewall default allows, info when deny-default protects it but bind is wider than needed |
| `network.firewall_unreadable` | warning | Firewall state could not be read, so listener exposure is unknown |
| `network.listeners_unreadable` | warning | Neither `ss` nor `/proc/net/tcp*` could be read, so listening sockets are unknown |
| `time.unsynchronised` | warning | The host's clock is not being synchronised |
| `disk.space_low` | warning / critical | The root filesystem is running out of space (90%) or inodes (95%), and critical at 95% / 99% |
| `systemd.failed` | warning / critical | A systemd unit's last run failed; critical when the unit is one whose loss makes the host unreachable |
| `kernel.pending_reboot` | warning | A kernel is installed that is newer than the running one |
| `system.reboot_required` | warning | Reboot-required marker file present (e.g. `/run/reboot-required`) |
| `boot.preset_missing` | warning | A preset-driven boot flow has an installed kernel with no matching mkinitcpio preset |
| `packages.orphaned` | info / warning | Installed packages nothing requires; a kernel or boot-path package is a warning |
| `config.drift` | warning | A config file replaced by pacman (`.pacnew`/`.pacsave`) awaits review |
| `config.drift_unknown` | warning | The `/etc` scan could not be completed, so replaced config files are unknown |
| `config.world_writable` | critical / warning | A file or directory under `/etc` is world-writable; critical under `ssh/`, `sudoers.d/`, `pam.d/`, `systemd/system/` or `cron.d*` |
| `config.world_writable_unknown` | warning | The `/etc` scan could not be completed, so world-writable paths are unknown |
| `security.sensitive_path_permissions` | critical / warning / info | Sensitive local secret/state paths (LUKS keyfile, SSH host/user private keys, `~/.ssh` and `authorized_keys`, cloud/container credentials under `~`, docker socket, tailscale state) have unsafe permissions |
| `security.world_writable_sensitive_runtime` | critical | World-writable entry in a sensitive runtime directory (bounded top-level scan) |
| `security.sensitive_runtime_unknown` | warning | Could not inspect a sensitive runtime directory |
| `security.sensitive_path_unknown` | warning | A sensitive path exists but could not be stat/read, so its permissions are unknown |
| `security.passwordless_sudo` | critical / warning | A sudoers rule grants NOPASSWD; critical for full `ALL`, warning for narrow/expired grants |
| `firewall.disabled` | critical | UFW is installed but inactive, so host firewall rules are not filtering incoming connections |
| `firewall.default_allow` | critical / warning | The firewall default incoming policy is `allow`, or another policy the auditor cannot classify as safe |
| `packages.outdated` | info / warning / critical | 1–20, 21–100, over 100 pending package updates |
| `power.restore_disabled` | critical | Chipset is set to stay off when power returns |
| `power.register_unreadable` | warning | `setpci` reported `0xff` — an access failure, not a value |
| `power.register_missing` | warning | No readable register (not an Intel Mac, or no LPC device) |
| `power.unit_disabled` | warning | The boot unit that restores auto power-on is not enabled |
| `power.unit_failed` | critical | The boot unit is enabled but its last run did not succeed |

## Privileges

A check whose input could not be read says so. That matters because two of the
readers need root, and the safe-looking answer is the dangerous one: an
unread firewall looks exactly like a firewall with no SSH rules.

| Check | Works unprivileged | Needs root | Notes |
|---|---|---|---|
| `sshd.*` | partial | **yes** | reads `ufw status verbose`, a root-only wrapper on Arch/Omarchy |
| `firewall.*` | partial | **yes** | reads the same `ufw status verbose` default-policy line |
| `network.*` | partial | **yes** | reads listening sockets via `ss`, falling back to `/proc/net/tcp*`; reads firewall state; an unreadable source is reported as `network.listeners_unreadable` / `network.firewall_unreadable` |
| `security.*` | partial | **yes** | reads `/etc/shadow` and sudoers; an unprivileged run reports unknown/degraded findings instead of guessing |
| `config.*` | partial | **yes** | walks `/etc` for `*.pacnew`/`*.pacsave` and world-writable paths; an unreadable subtree makes the scan unknown |
| `auditor.degraded` | yes | no | summarizes readers that could not run, without another privileged read |
| `time.unsynchronised` | yes | no | reads synchronization state with `timedatectl show` and `systemctl is-active` |
| `packages.outdated` | yes | no | reads `checkupdates`; unavailable or failed commands are reported as unknown |
| `packages.orphaned` | yes | no | queries the package database with `pacman -Qdt` |
| `power.register_missing` | yes | no | reports an absent or unreadable register rather than a register value |
| `disk.space_low` | yes | no | `statvfs` on the root filesystem, standard library only |
| `systemd.failed` | partial | **yes** | `systemctl --failed` lists system units for everyone, but a root-only unit can be hidden from a user manager |
| `kernel.pending_reboot` | yes | no | `uname -r` and `pacman -Q`; no kernel package on a non-Arch host is not a finding |
| `boot.preset_missing` | partial | **yes** | reads hook/script text, bootloader marker file names and installed package names; no boot file is modified. On hosts where `/boot` is root-only (e.g. Omarchy's `0700` ESP), an unprivileged run cannot identify the bootloader and reports nothing rather than guessing; run as root for an authoritative answer |
| `system.reboot_required` | yes | no | checks known reboot marker paths; missing markers are not findings |
| `tailscale.*` | yes | no | reads the local Tailscale socket |
| `power.restore_disabled` | partial | **yes** | `setpci` reads PCI config space, which is root-only |
| `power.register_unreadable` | yes | no | reports the access failure rather than hiding it |
| `power.unit_*` | yes | no | `systemctl is-enabled` / `is-active` |

Run as root for an authoritative report:

```console
$ sudo volt-watch
```

Or grant one specific command through polkit and keep the auditor
unprivileged — see your distribution's polkit documentation.

## What it deliberately does not do

- **It does not fix anything.** Every finding carries a remedy string; applying
  it is a human decision.
- **It does not expose a service.** No listener, no agent, no remote API. It
  runs, prints, exits.
- **It does not expose secret material.** It inspects configuration and state;
  the account check reads `/etc/shadow` only to tell an empty password field
  from a real one, and never copies a hash or the file into a report.

## Running it on a schedule

A systemd timer is the intended deployment:

```ini
# ~/.config/systemd/user/volt-watch.timer
[Unit]
Description=Run volt-watch daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# ~/.config/systemd/user/volt-watch.service
[Unit]
Description=volt-watch audit

[Service]
Type=oneshot
ExecStart=/usr/local/bin/volt-watch
```

Note that the power-register check needs root to read the PCI config space.
Run it as root from a system unit if you want that check to be authoritative;
unprivileged, it reports `power.register_unreadable` instead of guessing.

## Development

Tests are the specification. Every behaviour was written as a failing test
first.

```bash
python -m pytest tests/ -q
```

### Keeping documentation current

`tests/test_documentation.py` statically inspects `Finding(check=...)`
constructors in `volt_watch/checks.py` and `volt_watch/auditor.py`, without
running an audit or a host reader. It compares the Checks table in both
directions, and expands Privileges table wildcards against the same names.
Every privileges pattern must match a real check, and every check must be
covered. `auditor.degraded` is included even though it is added outside
`auditor.CHECKS`. CLI-only baseline metadata (`auditor.no_baseline`) is
documented under Usage rather than treated as a host check.

Keep test counts out of this README and the separate profile README. Use
"the suite is the specification" and link to the current CI run instead
of copying a number that goes stale. The profile is maintained separately;
this repository does not fetch or test its contents. When updating that
profile, remove any manual test or finding count rather than maintaining
a second inventory of checks.

## License

MIT — see [LICENSE](LICENSE).
