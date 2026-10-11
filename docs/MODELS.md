# Models

## Selection criteria

Every model shipped in the default manifest meets three conditions: a US-headquartered lab, a license that permits local use and fine-tuning, and a GGUF quantization small enough to run inside the RAM budget on the target hardware. Chinese-origin models are excluded by design, which is a deliberate constraint with a known cost discussed at the end of this document.

## Default roster

| Role | Model | Lab | License | Why |
|------|-------|-----|---------|-----|
| Assistant, small tier | Gemma 4 E4B | Google DeepMind (US) | Apache 2.0 | Fits a 16 GB CPU-only machine at Q4. |
| Assistant, standard tier | Gemma 4 12B | Google DeepMind (US) | Apache 2.0 | Dense model, takes LoRA style adapters cleanly, comfortable at Q4 on 32 GB or any GPU. |
| Assistant, alternate | Olmo 3 7B | Allen Institute for AI (US) | Apache 2.0 | Published training corpus. Choose when data lineage matters more than raw quality. |
| Guardian | ShieldGemma 2B | Google DeepMind (US) | Gemma Terms | Purpose-built safety classifier, fast enough for CPU, Yes/No output Palisade reads as a probability. |
| Guardian, second opinion | Granite Guardian 3.3 8B | IBM (US) | Apache 2.0 | Stronger on prompt injection; used as an optional second classifier on the standard tier. |

Why a dense assistant rather than a mixture-of-experts model: a LoRA adapter on an MoE spreads its updates across experts that only fire on some tokens, so a style or policy adapter lands inconsistently. Gemma 4 12B is dense, so an adapter applies to every forward pass. This matters if you later add a house-voice adapter; see `docs/FINE-TUNING.md`.

## The VERIFY step

`config/models.yaml` ships each model's `repo` field as `VERIFY/<name>`. This is intentional. The base weights come from the labs above, but the GGUF quantizations Palisade downloads are community conversions, and the Hugging Face repo that hosts a given quantization changes between quantizer releases. Rather than hardcode a repo that may move or be replaced, the manifest forces one deliberate check.

Before first install, for each model:

1. Find the current GGUF repo on Hugging Face for that model and quantization (for example a `Q4_K_M` build of Gemma 4 12B).
2. Confirm the uploader is one you trust and the file name matches the `file` field, or update the `file` field to match.
3. Replace `VERIFY/<name>` with the real repo id.

If the model's block has a `sha256:` line, the download is checked against it and rejected on a mismatch before anything is recorded. Otherwise Palisade trusts the first download and says so. After installation, Palisade records the file's SHA-256 in `manifest.lock`, and every run checks the file on disk against it and refuses to start on a mismatch. `palisade publish-hashes` turns a verified installation into published `sha256:` lines (README, Procedure I).

If you already hold vetted GGUF files, skip the repos entirely:

```bash
python -m palisade install \
  --model-url gemma4-12b=file:///models/gemma-4-12B-it-Q4_K_M.gguf \
  --model-url shieldgemma-2b=file:///models/shieldgemma-2b.Q8_0.gguf
```

## Swapping the guardian

ShieldGemma and Granite Guardian use different prompt templates. ShieldGemma expects the policy-question shape already in `config/policy.yaml`. Granite Guardian uses its own chat template with a risk-name argument. To switch guardians you need to adjust the `templates` block in `policy.yaml` to match the new model's expected input, and set the guardian's `positive_token` and `negative_token` in `models.yaml` if they differ. Run `python -m palisade eval` after any guardian change to re-measure precision and recall before trusting it.

## Running two guardians

The standard tier defines an optional `secondary_guardian`. The recommended pattern for high-severity categories (weapons, child safety, cyber-offense) is to treat a hit from either guardian as a block, because the two models have complementary blind spots: one catches prompt-injection patterns the other misses, and the other over-blocks some benign traffic that the first passes. For routine categories, a single guardian keeps latency down. This ensemble behavior is a policy choice; wiring a second guardian into the request path is a small extension of `server.py` and is left as a documented option rather than enabled by default, since it roughly doubles guardian latency.

## The cost of the US-only constraint

Independent evaluation of open guardian models has found the strongest recall on a Chinese-origin guardian, ahead of the US-origin options here. Excluding it is a sound sovereignty and supply-chain decision, but it does leave measurable recall on the table. Two things reduce the gap in practice: reading logprobs with a tuned threshold rather than accepting the model's default Yes/No, and running two complementary US guardians for the categories where a miss is most costly. Measure the result on your own `eval/cases.jsonl` rather than trusting any published number, since guardian performance does not track parameter count and does not transfer cleanly across taxonomies.
