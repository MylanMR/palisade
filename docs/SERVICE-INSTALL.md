# Installer reference

This document records exactly what each installer creates, so an administrator or assessor can check a machine against it. For step-by-step instructions, see Parts 1 and 3 of the README; for how the installers are built and signed, see `packaging/SIGNING.md`.

## Design

Every installer ships the same payload: a pinned Python runtime with Palisade's dependencies installed from `requirements.lock`, the application, and a signed llama.cpp model server. The models are downloaded on first run and checked against the SHA-256 values published in `models.yaml` before anything trusts them.

Service mode splits the work between two identities:

- A **setup job** running as root (SYSTEM on Windows) writes the things that define what Palisade trusts: the models, `manifest.lock`, and the first copy of the settings and policy. It runs at install and at every startup, and exits in seconds when nothing is missing.
- The **service** runs as a dedicated, non-administrative account. It reads everything above and writes only its own state: the audit log, logs, the reviewer token, eval reports, and compliance reports. While setup is still running, it serves a progress page instead of the assistant.

The service therefore cannot replace a model, edit the policy, or re-record a fingerprint, even if it were compromised. A setup job never re-trusts a changed file: anything that differs from its recorded or published hash stops setup with an error, and only an administrator's explicit `palisade install` records an intended change to settings or policy.

## macOS

| Item | Value |
|---|---|
| Package | `Palisade-<version>-macos-arm64.pkg` (inside the `.dmg`); component packages `com.palisade.core`, `com.palisade.mode.service`, `com.palisade.mode.desktop` |
| Program | `/opt/palisade` (root:wheel, not writable by others); `/Applications/Palisade.app` |
| Commands | `/usr/local/bin/palisade`, `/usr/local/bin/palisade-mode` (links into `/opt/palisade`) |
| Service account | `_palisade`, hidden, UID in 400-499, shell `/usr/bin/false`, no password |
| Audit group | `palisade-audit`, GID in 400-499; the installing user is added if an Administrator |
| Jobs | `/Library/LaunchDaemons/com.palisade.setup.plist` (root, runs at load), `/Library/LaunchDaemons/com.palisade.server.plist` (`_palisade`, kept alive) |
| Desktop mode | `/Library/LaunchAgents/com.palisade.desktop.plist`, run for each person who signs in |
| Settings, service mode | `/Library/Application Support/Palisade/config` |
| Data, service mode | `/Library/Application Support/Palisade/data` |

| Path (service mode) | Owner:group | Mode |
|---|---|---|
| `.../Palisade`, `config`, `data`, `data/models` | root:palisade-audit | 0750 |
| files in `config`, `data/models`, `manifest.lock`, `setup-status.json` | root:palisade-audit | 0640 |
| `data/audit`, `logs`, `state`, `eval`, `compliance` | _palisade:palisade-audit | 0750, files 0640 |

macOS gives a new file its folder's group, so files the root setup job creates stay readable by the service and reviewers. Both jobs run with umask 027. launchd has no equivalent of systemd's filesystem sandboxing, so the macOS install relies on file permissions alone.

## Windows

| Item | Value |
|---|---|
| Packages | `Palisade-<version>-windows-x64.msi`; `.exe` is a WiX bundle that shows the MSI's dialogs |
| Program | `C:\Program Files\Palisade` (standard Program Files permissions: users read, administrators write) |
| Command | `C:\Program Files\Palisade\bin` on the system PATH (`palisade.cmd`) |
| Service | **Palisade**, run by WinSW 2.12.0 as the virtual account `NT SERVICE\Palisade`, automatic (delayed) start, restarts on failure |
| Setup job | Scheduled task **Palisade Setup**, SYSTEM, at startup, no time limit |
| Audit group | Local group **Palisade Audit**; the installing user is added if a member of Administrators (silent installs: `PALISADE_REVIEWER`) |
| Desktop mode | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Palisade.lnk`, run for each person who signs in |
| Settings, service mode | `C:\ProgramData\Palisade\config` |
| Data, service mode | `C:\ProgramData\Palisade\data` |
| Remembered mode | `HKLM\Software\Palisade\Mode` (keeps the mode across upgrades) |

Permissions in `C:\ProgramData\Palisade` (inheritance removed at the root):

| Principal | `Palisade`, `config`, `data` and below | `data\audit`, `logs`, `state`, `eval`, `compliance` |
|---|---|---|
| SYSTEM | Full control | Full control |
| Administrators | Full control (requires an elevated session) | Full control (requires an elevated session) |
| Palisade Audit | Read and execute | Read and execute |
| NT SERVICE\Palisade | Read and execute | Modify |

Administrators keep full control, reachable only through UAC elevation. An administrator's normal (unelevated) session uses the Palisade Audit membership and can read but not change the audit log.

## Linux (.deb and .rpm)

| Item | Value |
|---|---|
| Program | `/opt/palisade` (root:root, owned by the package) |
| Commands | `/usr/bin/palisade`, `/usr/sbin/palisade-mode` |
| Service account | `palisade`, system account, shell `/usr/sbin/nologin`, no home folder; added to `render` and `video` when present, for GPU access |
| Audit group | `palisade-audit` |
| Units | `palisade-setup.service` (root, oneshot), `palisade.service` (`palisade`); user unit `palisade.service` for desktop mode |
| Settings, service mode | `/etc/palisade` |
| Data, service mode | `/var/lib/palisade` |

| Path (service mode) | Owner:group | Mode |
|---|---|---|
| `/etc/palisade`, `/var/lib/palisade`, `/var/lib/palisade/models` | root:palisade-audit | 2750 |
| files in `/etc/palisade`, `models`, `manifest.lock`, `setup-status.json` | root:palisade-audit | 0640 |
| `audit`, `logs`, `state`, `eval`, `compliance` | palisade:palisade-audit | 2750, files 0640 |

The setgid bit makes files that the root setup job creates inherit the audit group. Both units add systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and `ReadWritePaths` limited to the folders each unit writes. Even if a file permission were set wrong, the service could write nowhere else.

The packages run no interactive steps: `palisade-mode service ACCOUNT` or `palisade-mode desktop` completes the setup. Removing the package stops and disables the units, removes the program, and leaves `/etc/palisade` and `/var/lib/palisade`.

## Upgrading from a 0.2.0 script install

The 0.2.0 service scripts kept everything under `/opt/palisade/data`. Choosing service mode after installing a package imports that folder's audit chain (unbroken, into an empty audit folder only) and its models (each checked against the published hashes as it is copied). On Linux, `palisade-mode` also retires the old unit in `/etc/systemd/system` and the old wrapper in `/usr/local/bin`, keeping them as `*.0.2.0`, because both would otherwise take precedence over the package's copies.

## Verification

**Linux .deb, tested 10 Oct 2026** on Ubuntu 24.04: installed the package, ran `palisade-mode service`, ran the setup job as root against a local model server, and checked permissions as three accounts. All 24 checks passed:

| Account | Allowed | Denied |
|---|---|---|
| Service (`palisade`) | verify the installation, append audit records, create the reviewer token | edit or add config files; overwrite, delete, or replace `manifest.lock` or a model; modify the bundled model server or its own code; run the setup job |
| Administrator in `palisade-audit` | read audit files, the reviewer token, and setup status; run `audit verify` and write reports to their own folder | append to, create in, or delete from the audit folder; edit the policy without `sudo` |
| Account outside the group | nothing | read audit files, the reviewer token, or config; run `audit verify` |

The same session verified that the service, with a model missing, serves the setup page and waits without trying to run setup itself; that the root setup job filled the gap and the service then started normally; that a second setup run exits in under a second; and that removing the package kept all data.

**Every release** runs install tests on clean GitHub runners for all three platforms before anything is published: install in service mode, confirm the service runs under its locked-down account and serves the setup page, confirm the account cannot write models (and, on Linux, the policy), uninstall, and confirm the audit data survived. Windows additionally checks that the service runs as `NT SERVICE\Palisade`.

**Not yet verified on real hardware:**

- The macOS Installation Type step: whether the two mode choices behave as radio buttons in Installer.app. The release workflow checks that Installer recognizes both choices, and the silent-install path does not depend on it.
- Whether a launchd daemon running as `_palisade` gets Metal GPU access on Apple Silicon. Check `logs/base-server.log` for Metal lines after setup; desktop mode always has it.
- The Windows MSI's dialogs, as seen by a person (CI installs silently).
