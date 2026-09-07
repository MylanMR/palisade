# Fine-tuning the assistant

Palisade separates the assistant from the guardian on purpose, and this is where that pays off. You can adapt the assistant's voice and output behavior without touching the safety layer, because the guardian is a different model in a different process.

## Why the separation matters here

Supervised fine-tuning erodes a model's built-in refusal behavior even when the training data is entirely benign. If your guardrail lived inside the assistant, every adapter you trained would quietly weaken it, and your compliance evidence would go stale the moment you merged. With the guard as an independent classifier, an adapter on the assistant changes how it writes, not whether the output is screened. The output check runs on the adapted model's answers exactly as before.

## What fine-tuning is good for

Adapt the assistant when you want output behavior baked into the weights rather than spent on context every call: a house voice, a fixed output format, domain vocabulary, consistent structure. Fine-tuning teaches behavior. It does not reliably teach facts, so do not fine-tune to make the model "know" a document set; that produces confident error. Use retrieval for facts and fine-tuning for behavior.

## Workflow on the target hardware

The training does not run inside Palisade. Train the adapter separately, then point Palisade at the merged model.

1. Build a dataset of prompt and response pairs in the target voice, a few hundred to a few thousand clean examples. For behavior that is mostly a set of prohibitions, add a preference pass (DPO or ORPO) where each example pairs a rejected answer with a chosen one, so the model learns the difference rather than only the target.
2. Train a LoRA or QLoRA adapter against the same base model Palisade uses. On Apple silicon use MLX; on a machine with an NVIDIA GPU, Unsloth or Axolotl. A small dense model like Gemma 4 12B adapts with modest data and overfits to a voice quickly, which is an advantage for style transfer.
3. Merge the adapter into the base weights and export to GGUF at the same quantization Palisade expects.
4. Install the merged model and re-lock:

   ```bash
   python -m palisade install --model-url gemma4-12b=file:///models/gemma-4-12B-voice-Q4_K_M.gguf
   ```

   This records the new file's hash in `manifest.lock`, so the adapted model is now the pinned, verified assistant.

## Re-verify after adapting

An adapter changes the assistant, so re-establish the evidence:

- Run `palisade eval` again. The guardian is unchanged, but confirming the numbers under the new manifest hash gives you a clean before-and-after and a report tied to the adapted build.
- Spot-check that the output check still fires on the adapted model by sending a prompt that should be blocked at output and confirming the decision and the audit record.

Because the manifest hash changes when the assistant changes, every audit record written after the swap is automatically attributable to the adapted build. The compliance trail follows the model without any extra bookkeeping.
