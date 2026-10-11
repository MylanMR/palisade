# Palisade

Palisade runs an AI assistant entirely on your own computer, with two protections built in:

1. **A guardian checks every exchange.** Before your message reaches the assistant, and again before the assistant's answer reaches you, a second AI model checks the text against a written content policy. If either check fails, you get a refusal instead.
2. **Every exchange is recorded in an audit log that shows tampering.** Each record is mathematically linked to the one before it, so editing, deleting, or reordering any record can be detected.

Nothing leaves your machine after setup. The models come from US-based labs under licenses that allow local use.

This guide takes you from a download to a running system, explains the separate account that keeps the audit log honest, and shows how to review the log.

**Contents**

- [Before you start](#before-you-start)
- [Part 1: Install Palisade](#part-1-install-palisade)
- [Part 2: Using Palisade](#part-2-using-palisade)
- [Part 3: The audit log service account](#part-3-the-audit-log-service-account)
- [Part 4: Audit log procedures](#part-4-audit-log-procedures)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)
- [What Palisade does not do](#what-palisade-does-not-do)

---

## Before you start

**Hardware.** A computer with 16 GB of memory or more and about 15 GB of free disk space. Palisade picks its models based on what it finds:

| Your machine | Assistant model | Guardian model |
|---|---|---|
| Apple Silicon Mac with 16 GB or more | Gemma 4 12B | ShieldGemma 2B |
| Any computer with 24 GB of memory or more | Gemma 4 12B | ShieldGemma 2B |
| An NVIDIA graphics card with 8 GB of memory or more | Gemma 4 12B | ShieldGemma 2B |
| Anything else with at least 16 GB of memory | Gemma 4 E4B | ShieldGemma 2B |

Apple Silicon Macs qualify at 16 GB because the GPU shares the computer's memory. Palisade measures graphics memory only on NVIDIA cards, so a machine with an AMD or Intel card is placed by its system memory. To override the choice, set `tier: small` or `tier: standard` in Palisade's `settings.yaml`.

Apple Silicon Macs use the built-in GPU automatically. Windows and Linux machines with an NVIDIA, AMD, or Intel graphics card use it automatically through Vulkan. Machines without one run on the processor, which works but answers slowly (often 20 seconds or more).

**Operating system.** macOS 13 or newer on Apple Silicon; Windows 10 or 11 (64-bit); or Linux with glibc 2.34 or newer (Ubuntu 22.04, Debian 12, Fedora 36, RHEL 9, or later).

**Two ways to run Palisade.** The installer asks which one you want, and you can switch later.

- **Service mode** runs Palisade in the background under a separate, locked-down account. That account writes the audit log; your administrator account can read it but cannot change it without elevating (`sudo`, or an elevated Windows session), which the operating system records. Choose this when the audit log needs to stand up to review. Part 3 explains it in detail.
- **Desktop mode** runs Palisade under each person's own login, with their own settings and data. It is simpler, and the audit log is still tamper-evident, but the person using Palisade also owns its log.

---

## Part 1: Install Palisade

### Option A: Use the installer (recommended)

The installers include everything Palisade needs: its own copy of Python, the application, and the model server. Each one is small (under 100 MB). The models, about 10 GB, download the first time Palisade starts, and each is checked against the fingerprint published with the release before it is used.

1. **Download the installer** for your computer from the repository's **Releases** page:

   | Computer | File |
   |---|---|
   | Mac with Apple Silicon | `Palisade-<version>-macos-arm64.dmg` |
   | Windows | `Palisade-<version>-windows-x64.exe` (or the `.msi` for managed deployment) |
   | Ubuntu, Debian | `palisade_<version>-1_amd64.deb` |
   | Fedora, RHEL | `palisade-<version>-1.x86_64.rpm` |

2. **Check the download** (optional, recommended). Every release includes `SHA256SUMS` and a build-provenance attestation that ties each file to the GitHub workflow run that built it:

   ```
   shasum -a 256 -c SHA256SUMS --ignore-missing          # macOS (sha256sum on Linux)
   gh attestation verify FILE -R MylanMR/palisade         # any platform with the GitHub CLI
   ```

   On Windows, `Get-FileHash .\Palisade-<version>-windows-x64.exe` prints the hash to compare with `SHA256SUMS`.

3. **Run the installer.**

   - **macOS:** open the `.dmg`, then open `Palisade-<version>-macos-arm64.pkg`. On the **Installation Type** step, choose **Service mode** or **Desktop mode**. Enter your password when asked.
   - **Windows:** run the `.exe`. On the **How should Palisade run?** page, choose **Service mode** or **Desktop mode**. Approve the administrator prompt.
   - **Linux:** install the package, then choose the mode. Linux package managers do not ask questions during installation, so choosing is a separate command:

     ```
     sudo apt install ./palisade_<version>-1_amd64.deb      # Ubuntu, Debian
     sudo dnf install ./palisade-<version>-1.x86_64.rpm      # Fedora, RHEL

     sudo palisade-mode service YOUR-ADMIN-ACCOUNT           # service mode
     palisade-mode desktop                                   # or desktop mode, as yourself
     ```

   In service mode, the account that runs the installer becomes the audit log reviewer if it is an administrator. Part 3 lists exactly what the installer creates.

4. **Open Palisade.** Use **Palisade** in Applications (macOS), the Start menu (Windows), or your applications menu (Linux), or go to **http://127.0.0.1:8080/** in a browser. This address only works on your own computer; nothing is reachable from your network.

5. **Wait for setup.** The first time, the page shows setup progress while the models download. Downloads resume where they stopped if the connection drops. When both models are verified, the page switches to Palisade on its own.

Palisade then starts automatically: at boot in service mode, at sign-in in desktop mode.

**No Hugging Face account is needed** for the default models. If you switch to a model that requires one, see "Download fails with 401, 403, or gated" under Troubleshooting.

**Coming from a source checkout** (such as an earlier `git clone` install)? Reuse its models and audit chain so nothing downloads twice and the audit history continues unbroken. In desktop mode: `palisade import ~/palisade/data`. In service mode, the installer does this for a 0.2.0 service install automatically; otherwise run `sudo palisade import ~/palisade/data` (on Windows, in an elevated terminal). Models are checked against the published fingerprints as they are copied, and the audit chain is copied only into an empty audit folder.

### Option B: Run from source (developers)

All commands go in a terminal: **Terminal** on macOS, your terminal app on Linux, or **PowerShell** on Windows. You need Python 3.9 or newer and Git.

1. **Get the code:**

   ```
   git clone https://github.com/MylanMR/palisade.git
   cd palisade
   ```

   Every command below assumes you are in that folder. `ls` should list `README.md`, `config`, `palisade`, and `scripts`.

2. **Check Python:** `python3 --version` (on Windows, `py --version`) should print `Python 3.9` or higher. The version Apple includes with its Command Line Tools (3.9) works, but Python 3.9 no longer receives security updates, so a newer Python from python.org or Homebrew is the better long-term choice.

3. **Choose a policy.** The policy decides what gets blocked, what gets flagged for review, and what is allowed. `config/policy.yaml` is the file Palisade enforces, and it starts as a copy of `config/policy.example-standard.yaml`, a broad, ready-to-use policy. `config/policy.example-blank.yaml` is a minimal skeleton for writing your own. To keep your real policy out of Git, put it in `config/policy.local.yaml`; Palisade uses that file in preference to `policy.yaml`, and Git ignores it. For your first run, leave it alone.

4. **Install and start:**

   ```
   bash scripts/bootstrap.sh                                         # macOS or Linux
   powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1    # Windows
   ```

   This sets up a private Python environment with exact, hash-verified package versions, downloads the model server and both models, checks each against the hashes published in `config/models.yaml`, records their fingerprints, and starts Palisade. The first run downloads about 10 GB. When you see `Palisade ready: http://127.0.0.1:8080/`, open that address.

5. **Stop and start again.** Press `Ctrl+C` in the terminal to stop. Run `bash scripts/bootstrap.sh` again to start; it skips the downloads, checks every file against its recorded fingerprint, and starts in seconds.

Every model in `config/models.yaml` used by default carries a published `sha256:` line, and the llama.cpp archives and servers carry published hashes per platform. A download that differs is rejected before anything is recorded. A model without a published hash is trusted on first download, and Palisade prints a note saying so. Either way, Palisade records each file's fingerprint after installation and refuses to start if a file ever changes.

---

## Part 2: Using Palisade

### Chatting

Type in the box at the bottom and press Enter (Shift+Enter for a new line). Under every answer, a short note shows what happened:

| You see | What it means |
|---|---|
| **Answered** | Both checks passed. |
| **Answered, flagged for review** | The exchange touched a category set to "flag" (such as personal data). You got the answer, and the record is marked for a reviewer. |
| **Blocked before reaching the model** | Your message failed the check. The assistant never saw it. |
| **Answer blocked before display** | The assistant's answer failed the check and was replaced with a refusal. |

The note also shows the **violation likelihood** the guardian assigned (0% to 100%) and the **audit record number** with its hash, a short fingerprint that links to the record before it.

### The panel on the right

**Assistant** shows which model is answering, how it is compressed ("Q4_K_M"), and whether it is running on the GPU or the processor. "Running" means it answered a health check in the last 15 seconds.

**Guardian** shows the checking model and its rules:

- "Screens your messages" and "Screens answers" should both be present. If either shows as off, a red warning appears, because content in that direction is going unchecked.
- The threshold line says when it blocks, for example "50% or higher."
- The scale shows where your last message (M) and last answer (A) scored. Markers far to the left of the red line mean comfortable margins.
- The session line counts messages checked, blocked, and flagged since startup.

**Policy** shows which policy file is in force, its version, and how many categories block or flag. Open "Categories and actions" to see each rule. A yellow note appears if you are running an unmodified example policy.

**Manifest** confirms the files on disk still match what was installed. "Check again" re-checks settings, policy, and the model server quickly. "Re-hash models" re-checks the multi-gigabyte model files and takes several seconds. "Export manifest" downloads the full fingerprint list, useful as evidence.

**Audit chain** shows whether the log is intact and how many records it holds. As you chat, your records appear as a linked chain: each one shows its own hash and the hash of the record it links to. "Verify now" recomputes the whole chain. "Open audit review" goes to the review page (Part 4).

---

## Part 3: The audit log service account

In desktop mode, the person using Palisade also owns the audit log. They could edit it, and only the hash chain would show that something changed. Service mode separates those duties:

| Account | Role |
|---|---|
| **Service account** (`_palisade` on macOS, `palisade` on Linux, the virtual account `NT SERVICE\Palisade` on Windows) | Runs Palisade and writes the audit log. Cannot log in, has no administrator rights, and cannot change its own code, settings, policy, models, or recorded fingerprints. |
| **Setup job** (runs as root, or SYSTEM on Windows) | Downloads and verifies the models and records their fingerprints, which the service account is not allowed to write. Runs at install and at each startup, and exits in seconds when nothing is missing. |
| **Audit group** (`palisade-audit`; `Palisade Audit` on Windows) | Members can read the audit log and the reviewer token. They cannot change either. |
| **Administrator** (you) | Added to the audit group to review. Changing anything requires elevation, which the operating system records. |
| **root / SYSTEM** | Break glass. Can do anything; off-machine anchors (Part 4) make any rewrite of history detectable afterward. |

### Where Palisade keeps its files

| | macOS | Windows | Linux |
|---|---|---|---|
| Program (read-only) | `/opt/palisade` | `C:\Program Files\Palisade` | `/opt/palisade` |
| Settings and policy, service mode | `/Library/Application Support/Palisade/config` | `C:\ProgramData\Palisade\config` | `/etc/palisade` |
| Data and audit log, service mode | `/Library/Application Support/Palisade/data` | `C:\ProgramData\Palisade\data` | `/var/lib/palisade` |
| Settings and policy, desktop mode | `~/Library/Application Support/Palisade/config` | `%LOCALAPPDATA%\Palisade\config` | `~/.config/palisade` |
| Data and audit log, desktop mode | `~/Library/Application Support/Palisade/data` | `%LOCALAPPDATA%\Palisade\data` | `~/.local/share/palisade` |

In the data folder: `audit/` holds the chain, `state/reviewer.token` the reviewer token, `logs/` the logs, `models/` the models, and `manifest.lock` the recorded fingerprints. A source checkout keeps everything in its own `config/` and `data/` folders.

The service-mode data folder is called **DATA** in the steps below.

### What the installer sets up

**macOS:** the hidden `_palisade` account (no password, no login shell) and the `palisade-audit` group; two launchd jobs in `/Library/LaunchDaemons`, `com.palisade.setup` (root) and `com.palisade.server` (`_palisade`); `palisade` and `palisade-mode` commands in `/usr/local/bin`; and **Palisade** in Applications.

**Windows:** the service **Palisade**, running as `NT SERVICE\Palisade` (Windows manages this account; it has no password and cannot sign in interactively); the scheduled task **Palisade Setup**, running as SYSTEM at startup; the local group **Palisade Audit**; folder permissions that give the service write access only to its audit, log, state, eval, and compliance folders; `palisade` on the system PATH; and **Palisade** in the Start menu.

**Linux:** the `palisade` system account (no login shell) and the `palisade-audit` group; the systemd units `palisade-setup.service` (root) and `palisade.service` (`palisade`), both hardened so they can write only their own folders; and the `palisade` and `palisade-mode` commands. `docs/SERVICE-INSTALL.md` lists every owner and permission.

### Confirm service mode works

1. **Sign out and back in.** Your audit group membership applies only to new sessions. Skipping this is the most common cause of "Permission denied" below.

2. **Confirm the service is running.**

   - macOS: `sudo launchctl print system/com.palisade.server | grep state` shows `state = running`.
   - Windows: `Get-Service Palisade` shows `Running`.
   - Linux: `systemctl status palisade` shows `active (running)`.

3. **Confirm the permissions.** Run these as yourself, without elevating.

   ```
   palisade audit verify
   ```
   Succeeds and reports the chain as intact (or empty, before your first message).

   macOS and Linux: `cat DATA/state/reviewer.token`. Windows: `Get-Content C:\ProgramData\Palisade\data\state\reviewer.token`. Prints a long random string, the reviewer token for Part 4. The file appears after the service first starts.

   macOS and Linux: `touch DATA/audit/test`. Windows: `New-Item C:\ProgramData\Palisade\data\audit\test`. **Fails** with "Permission denied" (or "Access is denied"). That failure is the point: you can read the audit log but not add to or change it.

4. **On a Mac, confirm the GPU is in use** once setup has finished and Palisade has started:

   ```
   grep -i metal "/Library/Application Support/Palisade/data/logs/base-server.log" | head -3
   ```

   Lines mentioning Metal mean the GPU is in use. If there are none, the service runs on the processor and answers are slow. Whether macOS gives a background service account access to the GPU could not be tested before release; please report which result you get. Desktop mode runs in your own session and always has the GPU.

### Switch modes later

```
sudo palisade-mode service YOUR-ADMIN-ACCOUNT        # macOS, Linux
sudo palisade-mode desktop
palisade-mode status
```

On Windows, in an elevated PowerShell:

```
& "C:\Program Files\Palisade\libexec\palisade-mode.ps1" -Mode service -Reviewer "$env:COMPUTERNAME\you"
& "C:\Program Files\Palisade\libexec\palisade-mode.ps1" -Mode desktop
```

Switching never deletes data. Service-mode and desktop-mode data live in different folders (see the table above), so each mode keeps its own audit history.

### Uninstall

| | Command |
|---|---|
| macOS | `sudo /opt/palisade/uninstall.sh` (add `--remove-accounts` to also delete `_palisade` and `palisade-audit`) |
| Windows | **Settings > Apps > Installed apps > Palisade > Uninstall**, or `msiexec /x Palisade-<version>-windows-x64.msi` |
| Linux | `sudo apt remove palisade` or `sudo dnf remove palisade` |

Uninstalling removes the program, the service, and its jobs. Settings and data, including the audit log, stay where they are: deleting audit records should be a deliberate decision, not a side effect of uninstalling.

### Deploying to many machines

- **macOS (MDM or Terminal):** `sudo installer -pkg Palisade-<version>-macos-arm64.pkg -target /` installs service mode. For desktop mode, add `-applyChoiceChangesXML desktop-mode.plist`, from the `.dmg`'s "For administrators" folder. Add a reviewer afterward with `sudo dseditgroup -o edit -a ACCOUNT -t user palisade-audit`.
- **Windows (Intune, Group Policy, msiexec):** `msiexec /i Palisade-<version>-windows-x64.msi /qn PALISADE_MODE=service PALISADE_REVIEWER="DOMAIN\user"`. Use `PALISADE_MODE=desktop` for desktop mode. Upgrades keep the mode chosen at first install.
- **Linux:** install the package, then run `palisade-mode` from your configuration management.

---

## Part 4: Audit log procedures

Two kinds of audit file exist, and the difference matters:

- **The chain** (`audit-*.jsonl` files) is the record of truth. Palisade writes one line per exchange. Never edit these files.
- **Review logs** are readable reports generated from the chain. Each one states whether the chain was intact when it was generated, and ends with its own fingerprint so later edits to the report can be detected.

With an installed copy, run commands as `palisade ...` in a terminal; it uses the files of the mode chosen at install (see the table in Part 3). In a source checkout, run `source .venv/bin/activate` in the palisade folder first, then use `python -m palisade ...` wherever this guide says `palisade ...`.

### Procedure A: Routine review in the browser

Suggested cadence: weekly, or whatever your organization's audit review policy requires.

1. Open **http://127.0.0.1:8080/review**.
2. Paste the reviewer token and select **Open review**.
   - Service mode: `cat DATA/state/reviewer.token` (Windows: `Get-Content C:\ProgramData\Palisade\data\state\reviewer.token`)
   - Desktop mode: the same file in your own data folder (Part 3 table); in a source checkout, `data/state/reviewer.token`
3. Read the summary at the top. **Chain** should say **Intact**. If it says **Broken**, stop and follow Procedure E.
4. Select **Flagged** and review each flagged exchange. Then select **Blocked** and look for patterns, such as repeated attempts in one category.
5. Select **Export review log** to download a report. A copy is also saved in the audit folder under `reports/`. File the downloaded copy wherever your review records belong.
6. Select **Export anchor** and store the file off this machine (Procedure C).
7. Select **Sign out of review** when finished.

Your logins, failed logins, and exports are themselves recorded in `logs/review-access.log` in the data folder. After ten failed logins in ten minutes, review login locks for ten minutes.

### Procedure B: Review from the command line

1. Check the chain:

   ```
   palisade audit verify
   ```

   `"intact": true` means every record still links correctly to the one before it.

2. Write a review log to your current folder:

   ```
   palisade audit report
   ```

   To see only blocked exchanges, add `--decision blocked`. Other filters: `flagged`, `answered`, `blocked_input`, `blocked_output`. To print to the screen instead of a file, add `--out -`.

3. Read the header. "Chain status: INTACT" and "Generated by" (your account name) are the two lines to check first.

Message text appears in reports only if `retain_content: full` is set in `config/settings.yaml` and you add `--include-content`. The default stores fingerprints of messages instead of the text, so reviewers see decisions and scores but not what was asked. Turning on full retention makes the audit log sensitive; decide deliberately.

### Procedure C: Export and store an anchor

**Why this matters.** The hash chain catches edits that leave the stored fingerprints alone. Someone with full control of the machine could edit a record and then recompute every fingerprint after it, producing a chain that passes `verify`. An anchor catches that: it records the chain's fingerprint at a moment in time, stored where this machine cannot reach it. Any later rewrite of earlier history no longer matches the anchor.

1. Export the anchor:

   ```
   palisade audit anchor --out anchor-2026-09-28.json
   ```

   Or select **Export anchor** on the review page.

2. Move the file off this machine: another computer, a USB drive kept separately, a ticket in your records system, or a printout. Storing it on the same machine defeats the purpose.
3. Keep every anchor. An old anchor can later prove that history up to that point has not changed since.

### Procedure D: Check an old anchor or a saved report

To confirm the log still matches an anchor you stored earlier:

```
palisade audit check-anchor anchor-2026-09-28.json
```

`"valid": true` with "chain passes through the anchored head" means nothing up to that anchor has changed.

To confirm a saved review log has not been edited since it was generated:

```
palisade audit check-report audit-review-20260928T120000Z.log
```

### Procedure E: If the chain shows as broken

A broken chain means at least one record was changed, removed, or reordered after it was written. Treat it as a possible security incident.

1. **Do not fix, delete, or regenerate anything.** The damaged files are the evidence.
2. Note the record number and file name shown in the message.
3. Copy the entire audit folder to separate storage (this needs `sudo`, or an elevated terminal on Windows, in service mode), keeping the originals in place.
4. Run `palisade audit check-anchor` against your most recent anchors. The newest anchor that still passes tells you the last point in time when history was intact.
5. Check who used `sudo` in that period. On macOS: `log show --predicate 'process == "sudo"' --last 7d`. On Linux: `journalctl _COMM=sudo --since "7 days ago"`. On Windows, review the Security event log for elevated processes (event 4688, which requires process-creation auditing) and for changes to the Palisade Audit group (events 4732 and 4733).
6. Report it through your organization's incident process.

### Procedure F: Rotate the reviewer token

Rotate it when a reviewer leaves or you suspect the token was exposed.

1. Delete `state/reviewer.token` in the data folder (service mode needs `sudo`, or an elevated terminal on Windows).
2. Restart Palisade:
   - macOS service: `sudo launchctl kickstart -k system/com.palisade.server`
   - Linux service: `sudo systemctl restart palisade`
   - Windows service: `Restart-Service Palisade` in an elevated PowerShell
   - Desktop mode: quit Palisade (sign out and back in, or end the `palisade run` process) and open it again
   - Source checkout: `Ctrl+C`, then `bash scripts/bootstrap.sh`
3. A new token is generated. Anyone with the review page open is returned to the sign-in screen and needs the new token.

### Procedure G: Add or remove a reviewer

Only add accounts that are administrators on this machine.

macOS:

```
sudo dseditgroup -o edit -a their-account -t user palisade-audit     # add
sudo dseditgroup -o edit -d their-account -t user palisade-audit     # remove
```

Linux:

```
sudo usermod -aG palisade-audit their-account                        # add
sudo gpasswd -d their-account palisade-audit                          # remove
```

Windows (elevated PowerShell):

```
Add-LocalGroupMember -Group "Palisade Audit" -Member "DOMAIN\their-account"
Remove-LocalGroupMember -Group "Palisade Audit" -Member "DOMAIN\their-account"
```

The person must log out and back in for the change to apply. When removing someone, also rotate the reviewer token (Procedure F), since they may have a copy.

### Procedure H: Change the policy on a service install

The service cannot change its own policy, so changes go through an elevated session and are recorded.

1. Edit `policy.yaml` in the service-mode settings folder (Part 3 table), for example:

   ```
   sudo nano /etc/palisade/policy.yaml                                           # Linux
   sudo nano "/Library/Application Support/Palisade/config/policy.yaml"          # macOS
   notepad C:\ProgramData\Palisade\config\policy.yaml                           # Windows, elevated
   ```

   Increase the `version:` value so audit records show which policy applied.

2. Record the new fingerprints. Palisade refuses to start while a file differs from its recorded fingerprint, so this step is required:

   ```
   sudo palisade install
   ```

   On Windows, run `palisade install` in an elevated terminal. It finds the models already present and only updates the fingerprints.

3. Restart the service (see Procedure F, step 2).
4. Confirm the Policy section of the panel shows the new version and "Matches lock."

### Procedure I: Publish verified model hashes

Do this once, after your first installation works, if you maintain a copy of Palisade that others install from. It turns your verified downloads into the reference every later install is checked against.

1. Confirm your install is intact:

   ```
   palisade doctor
   ```

   It should report that the installation matches `manifest.lock`.

2. Write the recorded fingerprints into `config/models.yaml`:

   ```
   palisade publish-hashes
   ```

   It refuses if any model or binary on disk has changed since installation. Add `--dry-run` to preview the result without writing it.

3. Cross-check each model hash independently. On Hugging Face, open the model file's page (for example, select `gemma-4-12B-it-Q4_K_M.gguf` in the repository's file list). The page shows the file's SHA256. It must match the `sha256:` line that was written for that model. If it does not, stop: the file you downloaded is not the one the publisher shows.
4. Record the updated `models.yaml`:

   ```
   palisade install
   ```

5. Commit `config/models.yaml`.

The llama-server hash is published per platform (for example, `macos-arm64`). Installs on other platforms still trust their first download until someone publishes a hash from that platform.

---

## Command reference

| Command | What it does |
|---|---|
| `palisade open` | Open Palisade in the browser, starting it first in desktop mode. |
| `palisade doctor` | Show detected hardware, chosen models, and whether files match their fingerprints. |
| `palisade install` | Record intended changes to settings or policy (and, in a source checkout, download models). |
| `palisade setup` | Installed copies: download and verify missing models. Setup normally runs on its own. |
| `palisade import FOLDER` | Reuse models and the audit chain from a source checkout's `data` folder. |
| `palisade run` | Start Palisade in the foreground. |
| `palisade-mode service ACCOUNT`, `palisade-mode desktop`, `palisade-mode status` | Installed copies on macOS and Linux: switch or show the mode (Part 3). |
| `bash scripts/bootstrap.sh` | Source checkout: set up, download, and start. Safe to rerun. |
| `palisade eval` | Test the guardian against labeled examples and report its accuracy. |
| `palisade benchmark` | Score this installation against the NIST AI Risk Management Framework. |
| `palisade publish-hashes` | Write verified model and binary fingerprints into `models.yaml` (Procedure I). |
| `palisade audit verify` | Recompute the audit chain. |
| `palisade audit report` | Write a readable review log. |
| `palisade audit anchor` | Export the chain's current fingerprint for off-machine storage. |
| `palisade audit check-anchor FILE` | Confirm the chain still matches a stored anchor. |
| `palisade audit check-report FILE` | Confirm a saved review log was not edited. |
| `palisade audit permissions` | Reset permissions on existing audit files. |

In a source checkout, prefix these with `python -m` after `source .venv/bin/activate`.

In service mode, `install`, `setup`, `import`, and `benchmark` change root-owned files, so run them with `sudo` (on Windows, in an elevated terminal). `eval` starts its own copies of the models on the same ports as the service, so stop the service first (`sudo launchctl bootout system/com.palisade.server` on macOS, `sudo systemctl stop palisade` on Linux, `Stop-Service Palisade` on Windows), run `sudo palisade eval`, then start the service again.

---

## Troubleshooting

**`pip: command not found`.** Use `python3 -m pip` instead of `pip`. macOS names the command differently.

**The setup page says "Setup stopped."** Usually a download failed: no network, or the server was unavailable. Parts already downloaded are kept. Retry by restarting Palisade (service mode: restart the computer, or run `sudo palisade setup`; desktop mode: open Palisade again). The message on the page and `logs/setup.log` in the data folder give the reason.

**The setup page says "A file changed since it was verified."** A model, the model server, a setting, or the policy differs from its recorded fingerprint. Palisade will not start and does not re-trust changed files on its own. If you changed settings or the policy on purpose, run `sudo palisade install` (Procedure H) to record it. If you did not, find out what changed before going further; Procedure E applies the same thinking to the audit log.

**Download fails with 401, 403, or "gated."** The model requires a Hugging Face account and accepted terms. The default models do not. Create a Read token at huggingface.co/settings/tokens, accept the model's terms on its page, then provide the token: set `HF_TOKEN`, or put it in a file named `hf-token` in Palisade's settings folder (service mode; make it readable only by root and the audit group), or sign in with the Hugging Face CLI (desktop mode and source checkouts). Palisade sends the token only to Hugging Face, never to the storage servers it redirects to.

**Download fails with 404.** A model repository or file name has changed. Check the names in `config/models.yaml` against the Hugging Face page, character for character.

**"Refusing to start; installation does not match manifest.lock."** A model, the model server, or a settings or policy file changed since installation. If you changed settings or policy on purpose, run `palisade install` again to record the new fingerprints. If you did not, find out what changed before continuing.

**"Refusing to start; network exposure check failed."** `server.host` in `config/settings.yaml` is set to an address other machines can reach. Palisade refuses this by default because its web pages assume local-only access: traffic is not encrypted, and the page gives a session token to any browser that loads it. Set `host` back to `127.0.0.1`. To use Palisade from another computer, see the next entry.

**Using Palisade from another computer.** Keep Palisade local and reach it through an SSH tunnel, which encrypts the connection and requires your login on the Palisade machine. On the Palisade machine, enable SSH (on a Mac: System Settings > General > Sharing > Remote Login). From the other computer, run:

```
ssh -L 8080:127.0.0.1:8080 your-account@palisade-machine
```

While that session is open, http://127.0.0.1:8080/ on the other computer reaches Palisade. If you have instead placed Palisade behind a reverse proxy that adds encryption and a login, you can set `allow_remote: true` under `server:` in `settings.yaml`; Palisade then starts with a warning. It never starts on a network address with `require_token: false`.

**"Does not match the hash published in config/models.yaml."** A downloaded or hand-placed model or model-server file is not the one the published hash describes. Palisade moved it aside with a `.rejected` suffix and installed nothing. Do not rename it back. Check the repository and file name in `models.yaml`, download again, and if it still fails, compare against the SHA256 shown on the Hugging Face file page.

**"THESE PACKAGES DO NOT MATCH THE HASHES" during setup.** A Python package downloaded during setup is not the exact file recorded in `requirements.lock`. Stop and try again later or from another network; if it persists, report it (see `SECURITY.md`). Do not bypass it by installing from `requirements.txt`.

**The panel shows "Not responding."** A model server stopped. Check `logs/base-server.log` or `logs/guardian-server.log` in the data folder (Part 3 table), then restart Palisade.

**Answers take a very long time.** The models are running on the processor. On a Mac in service mode, see Part 3, "Confirm service mode works," step 4.

**macOS says the installer "cannot be opened because it is from an unidentified developer."** You opened an unsigned test build. Released installers are signed and notarized by Apple. Download the release from the Releases page instead.

**"Permission denied" reading the reviewer token after the service install.** Log out and back in so your audit group membership applies.

**"That token was not accepted" on the review page.** Copy the token again. It is one long line with no spaces. If the token was rotated, the old one no longer works.

---

## Security defaults

A fresh install or clone is locked down before anyone changes a setting:

- It listens only on this machine (`127.0.0.1`) and refuses to start on a network address unless you explicitly opt in.
- Every API call needs a session token, and audit review needs a separate reviewer token.
- Messages are stored in the audit log as fingerprints, not text.
- Python packages install at exact versions and are checked against recorded hashes; models and the model server are checked against published hashes where they exist, and against their recorded fingerprints on every start.
- Audit files are readable only by their owner and the audit group.
- Released installers are signed (Apple Developer ID with notarization, Authenticode on Windows, OpenPGP on Linux), built only by the repository's release workflow, and published with checksums and build-provenance attestations. Every executable and library inside them is signed too, and Palisade's startup check covers the signed files.
- The installers bundle their own Python and model server, pinned by hash in `packaging/inputs.yaml`, so nothing on the computer's own `PATH` is used and nothing is downloaded at run time except the models, which are checked against published hashes.

To report a vulnerability, see `SECURITY.md`.

## What Palisade does not do

Stating the limits plainly is part of making the audit trail trustworthy.

- **The guardian can be wrong.** It is a classifier, and classifiers make mistakes in both directions. `palisade eval` measures how often, on your own test cases.
- **Guardrails limit behavior, not knowledge.** Blocking an answer does not remove what the assistant's model knows.
- **The audit log shows tampering; it does not prevent it.** An administrator with `sudo` or root can alter files. The chain and your off-machine anchors make that detectable afterward.
- **A one-person installation holds every role.** Service mode separates the accounts, but if you are the only administrator, the separation is technical rather than organizational.
- **The NIST benchmark shows where Palisade supplies evidence.** It is not an assessment result or a certification.

---

## More documentation

- `docs/AUDIT-REVIEW.md`: the audit model in depth, with a NIST SP 800-53 control mapping
- `docs/SERVICE-INSTALL.md`: exactly what each installer creates, with owners and permissions
- `packaging/SIGNING.md`: how releases are built, signed, notarized, and verified
- `packaging/windows/README.md`: Windows installer details and WiX licensing
- `docs/ARCHITECTURE.md`: how requests flow and why the design is shaped this way
- `docs/MODELS.md`: model choices, provenance, and licenses
- `docs/COMPLIANCE.md`: the NIST AI RMF crosswalk and benchmark
- `docs/FINE-TUNING.md`: adapting the assistant without weakening the guardian

## License

Apache 2.0 for the Palisade code. Each model has its own license, which you accept when you download it; this repository contains no model weights.
