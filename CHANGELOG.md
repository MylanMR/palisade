# Changelog

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
