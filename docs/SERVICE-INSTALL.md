# Service install reference

This document records exactly what the service installers create, so an administrator or assessor can check the result against it. For step-by-step instructions, see Part 3 of the README.

## What the installers create

| Item | macOS | Linux |
|---|---|---|
| Service account | `_palisade`, hidden, UID in 400-499, shell `/usr/bin/false`, no password | `palisade`, system account, shell `/usr/sbin/nologin`, no home directory |
| Audit group | `palisade-audit`, GID in 400-499 | `palisade-audit`, system group |
| Service definition | `/Library/LaunchDaemons/com.palisade.server.plist` | `/etc/systemd/system/palisade.service` |
| Command wrapper | `/usr/local/bin/palisade` | `/usr/local/bin/palisade` |
| Code and config | `/opt/palisade` | `/opt/palisade` |
| Data | `/opt/palisade/data` | `/opt/palisade/data` |

The installers refuse to run unless the reviewing account is an administrator (a member of `admin` on macOS; `sudo`, `wheel`, or `admin` on Linux). They require models to be installed in the checkout first and copy them rather than downloading again. An existing audit chain is copied too, so history continues unbroken, and the original is left in place.

## Ownership and permissions

| Path | Owner:group | Mode | Service can | Audit group can |
|---|---|---|---|---|
| `/opt/palisade` (code, config, policy, venv) | root | files 0644, dirs 0755 | read | read |
| `/opt/palisade/data` | root:palisade-audit | 0750 | enter | enter |
| `data/bin`, `data/models` | root:palisade-audit | files 0640 (binary 0750) | read | read |
| `data/manifest.lock` | root:palisade-audit | 0640 | read | read |
| `data/audit`, `data/logs`, `data/state`, `data/eval`, `data/compliance` | service:palisade-audit | dirs 2750, files 0640 | read, write | read |

The service runs with umask 027. Because the service's writable directories sit inside a root-owned directory, the service cannot replace `manifest.lock` or the models by deleting and recreating them.

The Linux unit adds `ProtectSystem=strict` with `ReadWritePaths` limited to the five writable directories, plus `NoNewPrivileges`, `ProtectHome`, and `PrivateTmp`. Even if a file permission were set wrong, the service could not write anywhere else. launchd has no direct equivalent, so the macOS install relies on file permissions alone.

## Verified behavior

The Linux installer was run and tested as three accounts before release. Each row was checked:

| Account | Action | Result |
|---|---|---|
| Service | Append an audit record | Allowed |
| Service | Modify the policy, overwrite or delete `manifest.lock`, write into models, modify its own code | Denied |
| Administrator in audit group | Read audit files and the reviewer token; run `audit verify`, `audit report`, `audit anchor`, `audit check-anchor` | Allowed |
| Administrator in audit group | Append to, create in, or delete from the audit directory; edit the policy without `sudo` | Denied |
| Account outside the group | Read audit files or the reviewer token; run `audit verify` | Denied |

The macOS installer uses the same layout and permissions but relies on `dscl`, `dseditgroup`, and `launchctl`, which were unavailable in the test environment. It passed a syntax check only. After installing on a Mac, run the checks in README Part 3, macOS step 5, which reproduce the most important rows of this table.

One open question on macOS: whether a launchd daemon running as a non-login account gets Metal GPU access. Check `data/logs/base-server.log` for Metal initialization lines. Without them, the model server runs on the CPU.

## Changing an installed system

- **Policy or settings:** edit under `/opt/palisade/config` with `sudo`, run `sudo palisade install` to record new fingerprints, then restart the service.
- **Upgrading Palisade:** update your checkout, then rerun the installer. It replaces the code in `/opt/palisade` and leaves `/opt/palisade/data` alone.
- **Uninstalling (macOS):** `sudo scripts/service/macos/uninstall.sh` stops the service and removes the launchd job and wrapper. Add `--remove-accounts` to delete the service account and group. Code and audit data stay in `/opt/palisade` until you remove them.
- **Uninstalling (Linux):** `sudo systemctl disable --now palisade`, then remove `/etc/systemd/system/palisade.service` and `/usr/local/bin/palisade`. Audit data stays in `/opt/palisade/data`.

## Windows (manual, untested)

Windows is not scripted, and the steps below have not been tested. They describe the equivalent setup using Windows-native concepts, as a starting point for an administrator comfortable with PowerShell and ACLs.

Palisade's own permission-setting code only runs on macOS and Linux. On Windows, folder ACLs do that job.

1. **Create the audit group and add the reviewing administrator** (elevated PowerShell):

   ```powershell
   New-LocalGroup -Name "palisade-audit" -Description "Palisade audit readers"
   Add-LocalGroupMember -Group "palisade-audit" -Member "YOUR-ACCOUNT"
   ```

2. **Place code and data.** Copy the checkout, without `data`, `.venv`, or `.git`, to `C:\Program Files\Palisade`, where standard users can read but not write by default. Create a virtual environment there and install `requirements.txt`. Copy `data\bin`, `data\models`, and `data\manifest.lock` from your checkout into `C:\ProgramData\Palisade\data`.

3. **Run as a service under a virtual service account.** Use a service wrapper such as NSSM to run `C:\Program Files\Palisade\.venv\Scripts\python.exe -m palisade run` as the account `NT SERVICE\Palisade`, with these environment variables:

   ```
   PALISADE_ROOT=C:\Program Files\Palisade
   PALISADE_DATA=C:\ProgramData\Palisade\data
   PYTHONPATH=C:\Program Files\Palisade
   ```

4. **Set folder permissions.** Remove inherited permissions from the data folder, grant read access broadly, then grant the service write access only where it needs it:

   ```powershell
   $d = "C:\ProgramData\Palisade\data"
   icacls $d /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "palisade-audit:(OI)(CI)RX" "NT SERVICE\Palisade:(OI)(CI)RX"
   foreach ($sub in "audit","logs","state","eval","compliance") {
     New-Item -ItemType Directory -Force "$d\$sub" | Out-Null
     icacls "$d\$sub" /grant "NT SERVICE\Palisade:(OI)(CI)M"
   }
   ```

Windows Administrators keep full control in this layout, reachable through an elevated (UAC) session. That matches the "administrators can always get access, and doing so is a deliberate act" model on the other platforms. Elevation events appear in the Windows Security event log if the corresponding audit policy is enabled.
