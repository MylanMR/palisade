# Audit review

Palisade keeps two kinds of audit artifact, and the difference matters.

The **chain** (`data/audit/audit-*.jsonl`) is the record of truth. Each line is one exchange, hashed together with the line before it. It is built for machines to verify and is never reformatted, because reformatting would break verification.

The **review log** is generated from the chain for people to read. It carries the chain's verification result and head hash at the moment it was generated, plus a SHA-256 of its own contents on the last line, so a saved review log can be checked for edits later.

## Roles

| Account | Can | Cannot |
|---|---|---|
| Service account (`_palisade` on macOS, `palisade` on Linux) | Run Palisade, append audit records, write logs and state | Change code, config, policy, models, or `manifest.lock`; log in |
| Administrator in `palisade-audit` | Read audit files and the reviewer token, run review commands, export reports and anchors to their own folders | Change or delete audit records, or change config, without `sudo` |
| Any other account | Nothing in the data directory | Read audit records or the reviewer token |
| root | Anything | Rewrite history without detection, provided an off-box anchor exists |

Administrators can always reach the data with `sudo`. That is deliberate: recovery and retention are legitimate administrative work. What the design guarantees is that administrator access is a deliberate, logged act (every `sudo` is recorded by the operating system), and that any alteration to the chain is detectable.

## Reviewing in the browser

Open `http://127.0.0.1:8080/review` and paste the reviewer token. The token lives in `state/reviewer.token` in the data folder: `/var/lib/palisade` (Linux), `/Library/Application Support/Palisade/data` (macOS), or `C:\ProgramData\Palisade\data` (Windows) in service mode; see the README's Part 3 table for desktop mode and source checkouts. The file is readable only by the service account and the audit group, so web review requires the same group membership as reading the files on disk.

The review page shows chain status, counts, and records, with filters for flagged, blocked, and answered exchanges. **Export review log** downloads the text log and saves a copy under `data/audit/reports/`. **Export anchor** downloads the current head hash. Logins, failed logins, and exports are recorded in `data/logs/review-access.log`. Ten failed logins in ten minutes locks review login for ten minutes.

To rotate the reviewer token, delete `reviewer.token` and restart Palisade; a new one is generated.

## Reviewing from the command line

```
palisade audit verify                       # recompute the chain
palisade audit report                       # write ./audit-review-<time>.log
palisade audit report --decision blocked    # only blocked exchanges
palisade audit report --out -               # print to the terminal
palisade audit check-report <file>          # confirm a saved report was not edited
palisade audit anchor --out anchor.json     # export the head hash
palisade audit check-anchor anchor.json     # confirm history still passes through it
palisade audit permissions                  # repair modes on existing audit files
```

With an installed copy, `palisade` is on the PATH and uses the files of the mode chosen at install. In a source checkout, run these as `python -m palisade ...` from the repo.

Message text appears in reports only when `retain_content: full` is set in `settings.yaml` and `--include-content` is passed. With the default `hashes`, a reviewer sees decisions, scores, and categories, but not what was asked.

## Anchors: the control that catches a full rewrite

The chain on its own detects an edit that leaves the stored hashes alone. It cannot detect an attacker with write access who edits a record and then recomputes every hash after it, because the rewritten chain is internally consistent. `palisade audit verify` passes on such a chain.

An anchor closes that gap. It records the head hash and the record count at a point in time. `check-anchor` recomputes the chain from the start and confirms it still arrives at the anchored hash at the anchored position. A rewrite of any earlier record changes that hash, so the check fails. The test suite demonstrates this case explicitly.

An anchor is only useful if the machine cannot change it. Store anchors on another system, on removable media, in a ticket, or on paper. A reasonable routine is to export one at each review, and to keep the previous anchors: checking an old anchor proves history up to that point has not changed since.

## Permissions

Palisade creates audit files with mode `0640` and audit directories with `2750` (setgid, so new files inherit the audit group on Linux), and runs with umask `027`. On a desktop install these modes still apply, but your own login account owns the files, so they protect against other local accounts only. The service install described in `docs/SERVICE-INSTALL.md` is what separates the account that writes the log from the accounts that review it.

Windows does not use POSIX modes; the installer sets equivalent folder permissions. See the Windows section of `docs/SERVICE-INSTALL.md`.

## NIST SP 800-53 mapping

| Control | How Palisade supports it | Limit |
|---|---|---|
| AU-6 Audit record review, analysis, and reporting | Review page with filters; text review log | Review cadence and follow-up are the operator's process |
| AU-7 Audit record reduction and report generation | Filtered reports that preserve the original records | |
| AU-9 Protection of audit information | Service-owned files at `0640`; hash chain detects alteration; anchors detect full rewrites | root can alter files; detection depends on anchors kept off the machine |
| AU-9(4) Access by subset of privileged users | Read access limited to the audit group; changes require `sudo` | Administrators can still elevate; that act is logged by the OS, not by Palisade |
| AC-5 Separation of duties | Service account writes, administrators review, root is break glass | A single-person install holds every role; separation is structural, not organizational |
| AC-6 Least privilege | Service account has no login, no admin rights, and write access to its state directories only | |
| CM-5 Access restrictions for change | Code, config, policy, and models are root-owned and read-only to the service; `manifest.lock` detects drift | |
| AU-11 Audit record retention | Uninstall never deletes audit data | Retention period and disposal are the operator's decision |

This mapping shows where Palisade contributes evidence. It is not an assessment result; the authorizing official's process determines that.
