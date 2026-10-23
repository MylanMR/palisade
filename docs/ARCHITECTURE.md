# Architecture

## Components

Palisade is one Python process that supervises two model servers and exposes an HTTP interface.

| Component | File | Responsibility |
|-----------|------|----------------|
| Hardware probe | `palisade/hardware.py` | Detect OS, arch, RAM, cores, GPU; pick backend and tier. |
| Fetcher | `palisade/fetch.py` | Download the pinned binary and models; write and verify `manifest.lock`. |
| Runtime | `palisade/runtime.py` | Launch, lock down, and health-check the two `llama-server` processes. |
| Harness | `palisade/harness.py` | Fixed rules around every model call: admission, clean-up, tokenizer probe, budget, server-held history, canary, fail closed. See `docs/HARNESS.md`. |
| Policy | `palisade/policy.py` | Turn `policy.yaml` into guardian prompts; resolve category actions. |
| Guardian | `palisade/guardian.py` | Score prompts and responses against the policy via logprobs. |
| Audit | `palisade/audit.py` | Append-only, hash-chained decision log with verification. |
| Server | `palisade/server.py` | Token auth, request lifecycle, UI, and API. |
| CLI | `palisade/__main__.py` | `install`, `run`, `doctor`, `verify`, `eval`. |

The assistant and the guardian each run as a separate `llama-server` instance from the same pinned `llama.cpp` build. On macOS and Linux each listens on a Unix socket in a folder only Palisade's account can open; on Windows each listens on `127.0.0.1`. Either way each requires a per-launch key, so only Palisade can call them. Keeping them in separate processes means either model can be swapped or resized without touching the other, and the guardian's behavior is independent of anything done to the assistant.

## Request lifecycle

1. The client calls `POST /api/chat` with a message and, after the first turn, a conversation id. Admission checks the Host header, the origin, and the body size; the server checks the bearer token or the HttpOnly session cookie; the rate limit and queue apply.
2. Harness. The message is normalized, hidden characters and template tokens are removed, each model's tokenizer is probed for surviving control tokens, and the token count is checked against the budget. History comes from Palisade's own record of the conversation.
3. Input check. The guardian scores the prompt against every category whose scope includes `input`. If the strongest matched action is `block`, generation is skipped and a policy refusal is returned. A `flag` marks the record and lets the request proceed.
   The guardian also scores the last few user messages joined together, which catches a request split across turns.
4. Generation. The assistant model produces a complete response. Streaming is deliberately disabled: the output check needs the whole answer before any of it is shown.
5. Output check. The harness removes and probes for control tokens and checks for the system-prompt canary, then the guardian scores the response against every category scoped to `output`. A `block` replaces the answer with the refusal; a `flag` marks the record.
6. Audit. Exactly one record is appended for the exchange, whatever the outcome (including requests rejected or stopped by the harness), carrying the decision, both guardian verdicts, the SHA-256 of the prompt and response, the policy version, and the manifest hash.
7. The response and the audit metadata (sequence number, record hash, previous hash) return to the client. The UI renders them under the answer.

## The audit chain

Each record's `hash` is `SHA-256(prev_hash + canonical_json(record_without_hash))`. Canonical JSON means sorted keys and no whitespace variance, so the hash is reproducible. The first record's `prev_hash` is 64 zeros. Records rotate to a new file by size, and the chain spans files because a new file's first record still points at the prior file's last hash.

This gives tamper-evidence, not tamper-proofing. An attacker who can write to the log can recompute the whole chain from the point of edit forward. What the chain guarantees is that any edit, deletion, or reordering is detectable unless every subsequent record is also rewritten, and it makes casual or partial tampering obvious. For stronger guarantees, periodically copy the head hash to append-only or external storage (a WORM share, a timestamping service, or a printed log); `palisade verify` prints the head hash for exactly this purpose.

## Threat model

What Palisade defends against:

- A user steering the assistant toward disallowed content. Both the prompt and the answer are screened by a separate model, and the block message replaces the answer rather than appending to it.
- Role injection and hidden instructions. Template tokens, invisible characters, and look-alike characters are removed by fixed code before any model sees the text, and each model's tokenizer confirms no control token survived. Clients cannot supply history, so earlier assistant turns cannot be forged.
- Bypassing the guardian by calling a model directly. The model servers accept requests only from Palisade, and any failed check stops the request.
- Prompt injection aimed at the assistant. The `prompt_injection` category screens input for instruction-override attempts. The guardian reads its own fixed template, so injected text in the user prompt is data to the guardian, not instructions.
- Silent drift in what is deployed. `manifest.lock` fingerprints the binary, both models, and all three config files. The stack refuses to start on a mismatch, so a swapped model or an edited policy cannot run unnoticed.
- After-the-fact denial or quiet log edits. The hash chain makes any change to history detectable.

What it does not defend against, and where responsibility sits:

- A privileged local attacker who can replace binaries and rewrite the entire log in place. Mitigate by shipping the log head hash off-box.
- The assistant model's own knowledge. Guardrails constrain behavior; they do not remove capabilities from the weights. A determined user plus a capable model is still a risk surface, which is why the guardian is conservative and every exchange is logged.
- Guardian error. No classifier is perfect. `docs/COMPLIANCE.md` covers calibration and the option of a second guardian for high-severity categories.

## Design choices

Two models instead of a system-prompt guardrail. A guardrail written into the assistant's system prompt degrades the moment the assistant is fine-tuned, and it produces no independent record. A separate classifier survives assistant changes and yields a score you can calibrate and report.

Logprob scoring instead of reading generated text. The guardian answers a Yes/No policy question, and Palisade reads the probability mass on the Yes and No tokens rather than the generated word. That turns the guard into a tunable classifier with a threshold you can move against your own labeled set, instead of a fixed pass/fail.

Vulkan as the default GPU backend on Windows and Linux. It runs on NVIDIA, AMD, and Intel from one binary, which suits a mixed fleet. CUDA is offered on Windows where it is meaningfully faster on NVIDIA hardware. Apple silicon uses Metal, compiled into the macOS build.

llama.cpp as the runtime. It is the most portable local inference engine, it takes GGUF quantized weights that fit the RAM budget, and it ships prebuilt server binaries for every target platform, which keeps install from requiring a compiler.

Local-only binding. The server binds to `127.0.0.1`. Desktop mode has no reason to accept off-box connections, and a bound loopback socket plus a per-run token keeps other local software from calling the API by accident.
