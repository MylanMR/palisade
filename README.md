# Palisade

A local LLM stack that enforces a written content policy on every exchange and records every decision in a tamper-evident audit log. It runs on one machine, offline after install, on Windows, Linux, or macOS.

Palisade is built to satisfy three requirements at once: sensible guardrails on input and output, an auditable record of what the system did and why, and a defensible mapping from behavior to policy. It uses only US-origin open-weight models under licenses that permit local use.

## What it is

Palisade is an orchestrator around two local model servers. A request passes through an input check, the assistant model, and an output check before anything reaches the user. Each of those steps, and the final decision, is written to an append-only log where each record is chained to the one before it by hash.

```
  browser / API client
        |
   [token check]
        |
   guardian: input check  ---- blocked? --> policy refusal
        |
   assistant model (llama.cpp)
        |
   guardian: output check ---- blocked? --> policy refusal
        |
   response  +  audit record (hash-chained)
```

The assistant model, the guardian model, the pinned llama.cpp build, and the three config files are all fingerprinted into `manifest.lock`. The stack refuses to start if anything on disk no longer matches. Every audit record carries the manifest hash and the policy version, so any single decision can be tied to the exact weights, binary, and policy that produced it.

## Target hardware

Designed for a single workstation with 16 or 32 GB of RAM, a 512 GB to 1 TB SSD, an Intel Core i5 or AMD Ryzen 5, running Windows 10/11, Linux, or macOS. GPU is optional. On a machine with a discrete NVIDIA, AMD, or Intel GPU, Palisade offloads to it automatically through CUDA (Windows) or Vulkan; on a CPU-only machine it runs on the processor.

The installer detects RAM and GPU and picks a tier:

| Tier | Trigger | Assistant | Guardian | Rough footprint |
|------|---------|-----------|----------|-----------------|
| small | 16 GB, CPU only | Gemma 4 E4B (Q4) | ShieldGemma 2B | ~6 GB models |
| standard | 32 GB or 8 GB+ VRAM | Gemma 4 12B (Q4) | ShieldGemma 2B | ~10 GB models |

## Quickstart

macOS or Linux:

```bash
git clone <your-fork> palisade && cd palisade
bash scripts/bootstrap.sh
```

Windows 10/11 (PowerShell):

```powershell
git clone <your-fork> palisade; cd palisade
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

The script builds a virtualenv, installs dependencies, downloads the pinned binary and models, records their hashes, and starts the server at `http://127.0.0.1:8080/`. First run downloads several GB; later runs verify hashes and start in seconds.

Before first install, open `config/models.yaml` and replace each `VERIFY/` repository id with the real Hugging Face GGUF repo (see `docs/MODELS.md`). GGUF conversions are community-published and their repo names move between quantizer releases, so this one manual step keeps the supply chain honest. If you already have GGUF files, point the installer straight at them: `python -m palisade install --model-url gemma4-12b=file:///path/to/model.gguf`.

### Choosing a policy

The policy is the file that decides what gets blocked, flagged, or allowed. The repository ships two example policies so you can start from whichever suits you:

- `config/policy.example-blank.yaml` — a minimal skeleton with the required category structure and generic rule text. Start here to write your own rules from scratch.
- `config/policy.example-standard.yaml` — a broader, ready-to-use policy covering the common hazard categories. Start here if you want a sensible default to build on.

Out of the box, `config/policy.yaml` (the file Palisade actually enforces) is a copy of the standard example, so the system runs with a useful policy on first launch. To switch, copy either example over `config/policy.yaml` and edit it.

If you want your working policy kept out of version control, copy it to `config/policy.local.yaml` instead. Palisade loads `policy.local.yaml` in preference to `policy.yaml` when it exists, and `.gitignore` excludes it, so your private rule text never enters a public repo. Either way, the hash of whichever policy is in force is recorded in `manifest.lock`, so the audit trail always ties a decision to the exact policy that produced it.

## Commands

| Command | What it does |
|---------|--------------|
| `python -m palisade doctor` | Print detected hardware, chosen tier, and whether the install matches `manifest.lock`. |
| `python -m palisade install` | Download the pinned binary and tier models, write `manifest.lock`. |
| `python -m palisade run` | Verify the install, launch both model servers, serve the UI and API. |
| `python -m palisade verify` | Walk the audit log and report whether the hash chain is intact. |
| `python -m palisade eval` | Run the guardian against `eval/cases.jsonl` and report precision and recall. |
| `python -m palisade benchmark` | Score the installation against the NIST AI RMF catalog and write a report. |

## API

Non-browser clients send the token printed at startup:

```bash
curl -s http://127.0.0.1:8080/api/chat \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"message":"Explain how TLS session resumption works."}'
```

The response carries the decision, the guardian scores, and the audit record's sequence number and hash.

## How the three criteria are met

Guardrails: a dedicated classifier model checks both the user prompt and the model's answer against the policy in `config/policy.yaml`, before the answer is shown. The guardian is a separate model from the assistant, so fine-tuning or swapping the assistant does not weaken the guard.

Auditable: every exchange produces one append-only record. Records are hash-chained, so editing, deleting, or reordering any record is detectable by `palisade verify`. Each record names the model, the policy version, and the manifest hash in force.

Policy compliance: the policy is a version-controlled file with stable category identifiers and per-category actions. `docs/COMPLIANCE.md` maps each category to the NIST AI RMF and gives the crosswalk an assessor needs.

## Documentation

- `docs/ARCHITECTURE.md` — components, request lifecycle, threat model, design choices
- `docs/MODELS.md` — model selection, provenance, licensing, the VERIFY step, swapping models
- `docs/COMPLIANCE.md` — policy structure, NIST AI RMF crosswalk, audit evidence, calibration
- `docs/FINE-TUNING.md` — adding a LoRA style adapter to the assistant without weakening the guard
- `compliance/nist_ai_rmf/` — machine-readable NIST AI RMF catalog, the benchmark engine, and the generated `REPORT.md`

## License

Apache 2.0. Model weights carry their own licenses; see `docs/MODELS.md`.
