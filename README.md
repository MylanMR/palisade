# Palisade

Palisade runs an AI assistant entirely on your own computer, with two protections built in:

1. **A guardian checks every exchange.** Before your message reaches the assistant, and again before the assistant's answer reaches you, a second AI model checks the text against a written content policy. If either check fails, you get a refusal instead.
2. **Every exchange is recorded in an audit log that shows tampering.** Each record is mathematically linked to the one before it, so editing, deleting, or reordering any record can be detected.

Nothing leaves your machine after setup. The models come from US-based labs under licenses that allow local use.

This guide takes you from a fresh download to a running system, then shows how to set up a separate account for the audit log and how to review it.

**Contents**

- [Before you start](#before-you-start)
- [Part 1: Install and run Palisade](#part-1-install-and-run-palisade)
- [Part 2: Using Palisade](#part-2-using-palisade)
- [Part 3: Set up the audit log service account](#part-3-set-up-the-audit-log-service-account)
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

Apple Silicon Macs qualify at 16 GB because the GPU shares the computer's memory. Palisade measures graphics memory only on NVIDIA cards, so a machine with an AMD or Intel card is placed by its system memory. To override the choice, set `tier: small` or `tier: standard` in `config/settings.yaml`.

Apple Silicon Macs use the built-in GPU automatically. Windows and Linux machines with an NVIDIA, AMD, or Intel graphics card use it automatically. Machines without one run on the processor, which works but answers slowly (often 20 seconds or more).

**Operating system.** macOS, Linux, or Windows 10/11.

**Software.** Python 3.9 or newer, and Git (optional; you can download a ZIP instead).

**An account at huggingface.co.** Free. This is where the models are downloaded from.

**Two ways to run Palisade.** You'll start with the first and can move to the second later.

- **Desktop mode** runs under your own login. It's the quickest way to try Palisade, and the audit log is still tamper-evident. Parts 1 and 2 cover it.
- **Service mode** runs Palisade under a separate, locked-down account. That account writes the audit log; your administrator account can read it but cannot change it without `sudo`. Use this when the audit log needs to stand up to review. Part 3 covers it.

---

## Part 1: Install and run Palisade

All commands go in a terminal: **Terminal** on macOS, your terminal app on Linux, or **PowerShell** on Windows.

### Step 1. Get the code

```
git clone https://github.com/MylanMR/palisade.git
cd palisade
```

Without Git, download the ZIP from the GitHub page, unzip it, and `cd` into the `palisade` folder. Every command in this guide assumes you are in that folder. You can confirm with `ls`, which should list `README.md`, `config`, `palisade`, and `scripts`.

### Step 2. Check Python

```
python3 --version
```

You should see `Python 3.9` or higher. The version Apple includes with its Command Line Tools (3.9) works. If you get "command not found," install Python from python.org (or `brew install python` on a Mac with Homebrew) and open a new terminal window.

On Windows, use `py --version` instead.

### Step 3. Sign in to Hugging Face

The models are hosted on Hugging Face, and some require you to accept the publisher's terms before downloading.

1. Create a free account at **huggingface.co** and sign in.
2. Visit each model page listed in Step 4 (for example `huggingface.co/lmstudio-community/gemma-4-12B-it-GGUF`). If a page asks you to agree to terms, agree.
3. Go to **huggingface.co/settings/tokens**, create a token with **Read** access, and copy it.
4. In your terminal, install the Hugging Face tools and sign in:

   ```
   python3 -m pip install -U huggingface_hub
   python3 -c "from huggingface_hub import login; login()"
   ```

   Paste the token when asked. Nothing appears on screen while you paste; that is normal. Press Enter. When asked "Add token as git credential?", answer `n`.

5. Confirm it worked:

   ```
   python3 -c "from huggingface_hub import whoami; print(whoami()['name'])"
   ```

   You should see your Hugging Face username. You only do this step once per computer.

### Step 4. Check the model locations

Open `config/models.yaml` in a text editor. Find the entries for the models your machine will use (see the table in "Before you start") and make sure each has a real `repo` value rather than one starting with `VERIFY/`.

These locations were confirmed working in September 2026:

| Entry in models.yaml | repo | file |
|---|---|---|
| `gemma4-12b` | `lmstudio-community/gemma-4-12B-it-GGUF` | `gemma-4-12B-it-Q4_K_M.gguf` |
| `shieldgemma-2b` | `mradermacher/shieldgemma-2b-GGUF` | `shieldgemma-2b.Q8_0.gguf` |

Two things to watch:

- The guardian file name uses dots: `shieldgemma-2b.Q8_0.gguf`. Type it exactly.
- Edit the block whose name matches the model. The `gemma4-12b` block needs the 12B repo; the `gemma4-e4b` block is for 16 GB machines and needs a different, smaller model. If you are on a 16 GB machine, find a current `gemma-4-E4B-it` GGUF repo on Hugging Face and fill it in.

Why this step exists: the quantized model files are published by community members, and their locations change over time. Checking them yourself once is part of trusting what you run. After the first download, Palisade records each file's fingerprint and refuses to start if a file ever changes.

### Step 5. Choose a policy

The policy decides what gets blocked, what gets flagged for review, and what is allowed. Palisade ships with two starting points in `config/`:

- `policy.example-standard.yaml`: a broad, ready-to-use policy. This is the default.
- `policy.example-blank.yaml`: a minimal skeleton for writing your own.

`config/policy.yaml` is the file Palisade actually enforces, and it starts as a copy of the standard example. To use the blank one instead, copy it over `policy.yaml`. For your first run, leave it alone.

If you want to keep your real policy out of Git, put it in `config/policy.local.yaml`. Palisade uses that file in preference to `policy.yaml` when it exists, and Git ignores it.

### Step 6. Install and start

macOS or Linux:

```
bash scripts/bootstrap.sh
```

Windows (PowerShell):

```
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

This one command sets up a private Python environment, downloads the model server and both models, records their fingerprints, and starts Palisade. The first run downloads about 10 GB, so give it time. When it finishes you'll see:

```
base ready on http://127.0.0.1:8081
guardian ready on http://127.0.0.1:8082

Palisade ready: http://127.0.0.1:8080/
```

### Step 7. Open Palisade

Open **http://127.0.0.1:8080/** in your web browser. This address only works on your own computer; nothing is reachable from your network.

Keep the terminal window open. Palisade runs inside it.

### Step 8. Stop and start again

- **To stop:** click in the terminal window and press `Ctrl+C`.
- **To start again later:** `cd` into the palisade folder and run `bash scripts/bootstrap.sh` again. It skips the downloads, checks every file against its recorded fingerprint, and starts in seconds.

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

## Part 3: Set up the audit log service account

In desktop mode, your own login account runs Palisade and owns the audit log. That means you could edit the log without anyone knowing, apart from the hash chain showing that something changed. Service mode separates those duties:

| Account | Role |
|---|---|
| **Service account** (`_palisade` on macOS, `palisade` on Linux) | Runs Palisade and writes the audit log. Cannot log in, has no administrator rights, and cannot change its own code, settings, policy, or models. |
| **Audit group** (`palisade-audit`) | Members can read the audit log and review it. They cannot change it. |
| **Administrator** (you) | Added to the audit group to review. Changing anything requires `sudo`, which the operating system records. |
| **root** | Break glass. Can do anything; off-box anchors (Part 4) make any rewrite of history detectable afterward. |

### Before you begin

- Complete Part 1 on this machine first. The installer reuses the models you already downloaded.
- You need an **Administrator** account (macOS) or an account in the `sudo`, `wheel`, or `admin` group (Linux). The installer refuses any other account as the reviewer.
- Stop the desktop copy (`Ctrl+C` in its terminal). Both copies use the same ports and cannot run at once.

### Steps on macOS

1. **Run the installer** from the palisade folder, naming your Administrator account:

   ```
   sudo scripts/service/macos/install.sh your-account-name
   ```

   Enter your password when asked. The installer:
   - creates the hidden `_palisade` account (no password, no login shell) and the `palisade-audit` group
   - adds your account to `palisade-audit`
   - copies Palisade to `/opt/palisade`, owned by root, so the service can read but not change it
   - moves your models, fingerprints, and existing audit log into `/opt/palisade/data`
   - installs a background service that starts at boot and restarts if it fails
   - installs a `palisade` command you can run from anywhere

2. **Log out and back in.** Your new group membership only applies to new sessions. Skipping this is the most common cause of "Permission denied" in the next steps.

3. **Confirm the service is running:**

   ```
   sudo launchctl print system/com.palisade.server | grep state
   ```

   You should see `state = running`. Then check the log:

   ```
   tail -n 20 /opt/palisade/data/logs/palisade.log
   ```

   Look for `Palisade ready`.

4. **Confirm the GPU is in use:**

   ```
   grep -i metal /opt/palisade/data/logs/base-server.log | head -3
   ```

   Lines mentioning Metal mean the GPU is in use. If there are none, the service is running on the processor and answers will be slow. This is the one part of the macOS installer that could not be tested before release; please report which result you get.

5. **Confirm the permissions work.** Run each of these as yourself, without `sudo`:

   ```
   palisade audit verify
   ```
   Should succeed and report the chain as intact.

   ```
   cat /opt/palisade/data/state/reviewer.token
   ```
   Should print a long random string. This is the reviewer token; you'll need it in Part 4.

   ```
   touch /opt/palisade/data/audit/test
   ```
   Should **fail** with "Permission denied." That failure is the point: you can read the audit log but not add to or change it.

6. **Open Palisade** at http://127.0.0.1:8080/ as before. It now runs in the background, so there is no terminal window to keep open.

To remove the service later: `sudo scripts/service/macos/uninstall.sh`. The audit data in `/opt/palisade/data` is kept on purpose; deleting audit records should be a deliberate decision.

### Steps on Linux

1. Run the installer, naming your administrator account:

   ```
   sudo scripts/service/linux/install.sh your-account-name
   ```

   It does the same things as the macOS installer, using a systemd service with extra restrictions: even if a file permission were wrong, the service can only write to its own audit, log, and state folders.

2. Log out and back in.

3. Confirm the service is running:

   ```
   systemctl status palisade
   journalctl -u palisade -n 20
   ```

   Look for `active (running)` and `Palisade ready`.

4. Run the three permission checks from macOS step 5. The paths are the same.

### Windows

Service mode is not scripted for Windows yet. `docs/SERVICE-INSTALL.md` describes the equivalent manual setup with a local service account and folder permissions.

---

## Part 4: Audit log procedures

Two kinds of audit file exist, and the difference matters:

- **The chain** (`audit-*.jsonl` files) is the record of truth. Palisade writes one line per exchange. Never edit these files.
- **Review logs** are readable reports generated from the chain. Each one states whether the chain was intact when it was generated, and ends with its own fingerprint so later edits to the report can be detected.

On a service install, run commands as `palisade ...`. In desktop mode, run `source .venv/bin/activate` in the palisade folder first, then use `python -m palisade ...` wherever this guide says `palisade ...`.

### Procedure A: Routine review in the browser

Suggested cadence: weekly, or whatever your organization's audit review policy requires.

1. Open **http://127.0.0.1:8080/review**.
2. Paste the reviewer token and select **Open review**.
   - Service mode: `cat /opt/palisade/data/state/reviewer.token`
   - Desktop mode: `cat data/state/reviewer.token` from the palisade folder
3. Read the summary at the top. **Chain** should say **Intact**. If it says **Broken**, stop and follow Procedure E.
4. Select **Flagged** and review each flagged exchange. Then select **Blocked** and look for patterns, such as repeated attempts in one category.
5. Select **Export review log** to download a report. A copy is also saved in the audit folder under `reports/`. File the downloaded copy wherever your review records belong.
6. Select **Export anchor** and store the file off this machine (Procedure C).
7. Select **Sign out of review** when finished.

Your logins, failed logins, and exports are themselves recorded in `data/logs/review-access.log`. After ten failed logins in ten minutes, review login locks for ten minutes.

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
3. Copy the entire audit folder to separate storage (this needs `sudo` in service mode), keeping the originals in place.
4. Run `palisade audit check-anchor` against your most recent anchors. The newest anchor that still passes tells you the last point in time when history was intact.
5. Check who used `sudo` in that period. On macOS: `log show --predicate 'process == "sudo"' --last 7d`. On Linux: `journalctl _COMM=sudo --since "7 days ago"`.
6. Report it through your organization's incident process.

### Procedure F: Rotate the reviewer token

Rotate it when a reviewer leaves or you suspect the token was exposed.

1. Delete the token file:
   - Service mode: `sudo rm /opt/palisade/data/state/reviewer.token`
   - Desktop mode: `rm data/state/reviewer.token`
2. Restart Palisade:
   - macOS service: `sudo launchctl kickstart -k system/com.palisade.server`
   - Linux service: `sudo systemctl restart palisade`
   - Desktop: `Ctrl+C`, then `bash scripts/bootstrap.sh`
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

The person must log out and back in for the change to apply. When removing someone, also rotate the reviewer token (Procedure F), since they may have a copy.

### Procedure H: Change the policy on a service install

The service cannot change its own policy, so changes go through `sudo` and are recorded.

1. Edit the policy:

   ```
   sudo nano /opt/palisade/config/policy.yaml
   ```

   Increase the `version:` value so audit records show which policy applied.

2. Record the new fingerprints. Palisade refuses to start while a file differs from its recorded fingerprint, so this step is required:

   ```
   sudo palisade install
   ```

   It finds the models already present and only updates the fingerprints.

3. Restart the service (see Procedure F, step 2).
4. Confirm the Policy section of the panel shows the new version and "Matches lock."

---

## Command reference

| Command | What it does |
|---|---|
| `bash scripts/bootstrap.sh` | Set up, download, and start (desktop mode). Safe to rerun. |
| `palisade doctor` | Show detected hardware, chosen models, and whether files match their fingerprints. |
| `palisade install` | Download models and record fingerprints. Rerun after changing settings or policy. |
| `palisade run` | Start Palisade (desktop mode, without the bootstrap steps). |
| `palisade eval` | Test the guardian against labeled examples and report its accuracy. |
| `palisade benchmark` | Score this installation against the NIST AI Risk Management Framework. |
| `palisade audit verify` | Recompute the audit chain. |
| `palisade audit report` | Write a readable review log. |
| `palisade audit anchor` | Export the chain's current fingerprint for off-machine storage. |
| `palisade audit check-anchor FILE` | Confirm the chain still matches a stored anchor. |
| `palisade audit check-report FILE` | Confirm a saved review log was not edited. |
| `palisade audit permissions` | Reset permissions on existing audit files. |

In desktop mode, prefix these with `python -m` after `source .venv/bin/activate`.

In service mode, `install` and `benchmark` change root-owned files, so run them with `sudo`. `eval` starts its own copies of the models on the same ports as the service, so stop the service first (`sudo launchctl bootout system/com.palisade.server` on macOS, `sudo systemctl stop palisade` on Linux), run `sudo palisade eval`, then start the service again.

---

## Troubleshooting

**`pip: command not found`.** Use `python3 -m pip` instead of `pip`. macOS names the command differently.

**`hf: command not found` or `huggingface-cli: command not found`.** The tool installed, but your terminal cannot find it. Use the Python form from Part 1, Step 3, which does not depend on it.

**Download fails with 401, 403, or "gated."** You have not accepted the model's terms on Hugging Face, or you are not signed in. Repeat Part 1, Step 3.

**Download fails with 404.** A model repository or file name has changed. Check the names in `config/models.yaml` against the Hugging Face page, character for character.

**"Refusing to start; installation does not match manifest.lock."** A model, the model server, or a settings or policy file changed since installation. If you changed settings or policy on purpose, run `palisade install` again to record the new fingerprints. If you did not, find out what changed before continuing.

**The panel shows "Not responding."** A model server stopped. Check `data/logs/base-server.log` or `guardian-server.log` (under `/opt/palisade/data/logs/` in service mode), then restart Palisade.

**Answers take a very long time.** The models are running on the processor. On a Mac in service mode, see Part 3, macOS step 4.

**"Permission denied" reading the reviewer token after the service install.** Log out and back in so your audit group membership applies.

**"That token was not accepted" on the review page.** Copy the token again. It is one long line with no spaces. If the token was rotated, the old one no longer works.

---

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
- `docs/SERVICE-INSTALL.md`: exactly what the service installers create, and the Windows setup
- `docs/ARCHITECTURE.md`: how requests flow and why the design is shaped this way
- `docs/MODELS.md`: model choices, provenance, and licenses
- `docs/COMPLIANCE.md`: the NIST AI RMF crosswalk and benchmark
- `docs/FINE-TUNING.md`: adapting the assistant without weakening the guardian

## License

Apache 2.0 for the Palisade code. Each model has its own license, which you accept when you download it; this repository contains no model weights.
