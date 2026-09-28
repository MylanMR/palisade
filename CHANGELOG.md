# Changelog

## 0.2.0

Audit review and separation of duties.

- **Service mode.** macOS (launchd) and Linux (systemd) installers create a locked-down service account that writes the audit log, and an audit group whose administrators can read it but not change it. Code, config, policy, and models become root-owned and read-only to the service. The Linux permission model was verified as three accounts (18 checks); the macOS installer passed a syntax check and needs confirmation on a Mac.
- **Review log.** `palisade audit report` writes a readable report from the chain, stamped with chain status, head hash, and the account that generated it, and ending with a self-hash that `audit check-report` uses to detect edits.
- **Anchors.** `audit anchor` exports the chain's head hash for storage off the machine; `audit check-anchor` recomputes the chain and confirms it still passes through the anchor. This detects a full rewrite in which every hash is recomputed, which internal verification alone cannot.
- **Review page.** `/review`, gated by a reviewer token readable only by the audit group, with filters, report and anchor export, an access log, and a login rate limit.
- **Runtime panel.** Readable model names, per-server health, a warning when a screening stage is off, a score scale for the latest message and answer, the active policy file with an example-policy notice, quick and full manifest checks with export, and a linked view of recent audit records.
- **Permissions.** Audit files are created 0640 and directories 2750; Palisade runs with umask 027.
- **Fixes.** Writing a file never changes the permissions of an existing folder. `/api/audit/tail` now requires the reviewer token. Record data renders without `innerHTML`.
- **Compatibility.** Python 3.9 is supported and tested in CI.
- README rewritten as a step-by-step guide for new users, with audit procedures. New `docs/AUDIT-REVIEW.md` and `docs/SERVICE-INSTALL.md`.

## 0.1.0

Initial release.

- Cross-platform local LLM stack (Windows 10/11, Linux, macOS) built on a pinned llama.cpp server.
- Dual-model architecture: a separate guardian classifier screens input and output on every exchange.
- Hardware auto-detection with small (16 GB, CPU) and standard (32 GB or GPU) tiers.
- US-origin open-weight models under permissive licenses; no Chinese-origin models.
- Tamper-evident, hash-chained audit log with verification.
- Supply-chain pinning via manifest.lock over the binary, models, and config; startup refuses on mismatch.
- Guardian evaluation harness reporting precision and recall against a labeled set.
- NIST AI RMF benchmark: machine-readable control catalog plus a scoring engine (`palisade benchmark`),
  verified against NIST.AI.100-1 with the NIST.AI.600-1 GenAI Profile.
- Local web UI showing the policy decision and audit record for each exchange.
- 18 tests covering the audit chain, tamper detection, policy engine, guarded request flow, and benchmark.
