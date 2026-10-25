# The model harness

Palisade puts two layers around every model call. The guardian is a model that judges content against the policy. The harness is fixed code that runs before and after each model call and enforces rules that need no judgment. A model can be persuaded, confused, or simply wrong, so the controls that must always hold live in the harness, where no prompt can reach them.

The harness was added in 0.4.0. Its code is `palisade/harness.py`, the model-server lockdown is in `palisade/runtime.py`, and the attack cases are in `eval/harness_cases.yaml`.

## Design rules

1. **Fail closed.** If any check cannot complete (a model server is down, a request times out, the guardian gives an answer that cannot be read as yes or no), the request ends with no model text returned, and the failure is written to the audit chain as `error`.
2. **Hold history on the server.** Earlier turns in a conversation live in Palisade's memory. A client names a conversation by its id and never sends past turns, so nobody can put words in the assistant's mouth.
3. **Use the model's own tokenizer as the referee.** Pattern lists cover the template tokens of common model families. The tokenizer probe asks each model's actual vocabulary whether a control token is present, which covers every template, including ones written after this code.
4. **Only Palisade can reach the models.** Each model server is locked so that the only path to a model runs through the guardian and the audit log.
5. **Settings can tighten, within bounds.** Numeric limits are configurable and clamped to fixed ranges. The core controls have no off switch.

## The layers, in request order

| Layer | What it does | What it stops |
|---|---|---|
| Admission | Accepts only Host headers Palisade answers to; refuses state-changing API calls from other origins or marked cross-site; caps request bodies as they stream in; applies a rate limit and a short bounded queue; allows one request per conversation at a time. | DNS-rebinding pages obtaining the session cookie, cross-site request forgery, memory exhaustion, runaway scripts. |
| Clean-up | Applies Unicode NFKC normalization, removes invisible format characters (zero-width, bidirectional overrides), tag characters, variation selectors, control characters, and chat-template control tokens such as `<start_of_turn>` or `<\|im_start\|>`. Repeats until nothing changes, so a token cannot be assembled from pieces that join only after a removal. | Role injection (faking a system or assistant turn), instructions hidden in invisible characters, look-alike characters that slip past the guardian. |
| Tokenizer probe | Tokenizes the cleaned message twice on each model server, once reading control-token text as control tokens and once as plain text. Any difference blocks the message. | Control tokens from templates the pattern list does not know. |
| Token budget | Counts the message with the assistant's tokenizer, rejects it over the limit, and drops the oldest turns so the whole context fits the window. Sizes the guardian's window so a full message and a full answer always fit. | Context overflow, and silent truncation that would leave text unscreened. |
| Server-held history | Sends the model only turns Palisade recorded itself. Blocked turns never enter the history. Three blocked or suspicious messages close the conversation. | Forged assistant turns, a blocked request resurfacing as context, repeated probing in one conversation. |
| Conversation screening | Runs the guardian over the last few user messages joined together, in addition to the new message on its own. Blocked messages count: they never reach the model, but they show where the conversation is heading. | A disallowed request split across several messages that each look harmless, including a follow-up sent after one part was blocked. |
| Per-category recheck | A combined guardian score under the threshold but at or above `recheck_above` (0.05 by default) is checked again one category at a time. Putting every category into one prompt dilutes the classifier, and the recheck recovers what it missed. | Borderline requests the combined check scores too low. |
| Override phrasing | A fixed set of patterns ("ignore all previous instructions", "developer mode", "print your system prompt", "I am your developer") marks the exchange for review. These are flagged and never blocked on phrasing alone, because people discuss these techniques for legitimate reasons. | Instruction-override attempts, which ShieldGemma scores low because it is trained on harmful-content categories. |
| Generation | Fixed parameters, a hard timeout, and model servers only Palisade can reach. | Clients changing sampling settings; hung requests. |
| Output checks | Removes control tokens from the answer, probes it, checks for the session canary and for long runs of the system prompt, then runs the guardian. | Answers that would inject into the next turn, disclosure of the system instructions. |
| Audit | Writes one record for every processed request, whatever the outcome, with a `harness` section saying what was removed, which conversation (by hash) and turn it was, how many prior turns were sent, and why anything was stopped. | Gaps in the record. |

Rate-limit and busy refusals return HTTP 429 and are counted on the Runtime panel. They are left out of the audit chain on purpose, so a flood of refused requests cannot bury the real records.

## Model-server lockdown

llama-server accepts prompts from anything that can connect to it. Without a lockdown, any program on the machine, or a web page using the browser as a relay, could talk to the model directly and skip the guardian.

- **macOS and Linux:** each server listens on a Unix socket in `state/run`, a folder with mode 0700 owned by the account running Palisade. There is no TCP port, so other accounts cannot connect and nothing can take over the port. If a server cannot use its socket, Palisade retries once on loopback and says so at startup and on the Runtime panel.
- **Windows:** each server listens on `127.0.0.1`. Palisade refuses to start if the port is already taken, then confirms the server that answers refuses a request without the key and accepts one with it.
- **Every platform:** a new random API key at each launch, passed through the environment because other accounts can read command lines from the process list. The environment is rebuilt from an allowlist, because llama-server reads `LLAMA_ARG_*` variables and one of them turns on built-in shell and file tools. Flags turn off the web UI, the slots endpoint, network downloads, and agent tools, and pin CORS to an origin no browser can have.
- **Linux service mode** also runs under systemd restrictions: no network beyond loopback (`IPAddressDeny=any`), no capabilities, and kernel, clock, and namespace protections. `systemd-analyze security` rates the unit 3.2 (OK), down from 8.3 (exposed) in 0.3.0.

## Outcomes you will see

| Decision | Meaning | HTTP status |
|---|---|---|
| `answered`, `flagged`, `blocked_input`, `blocked_output` | The guardian's decisions. A message the harness had to clean of attack-shaped content (template tokens, tag characters, selector runs) is at least `flagged`. | 200 |
| `rejected` | The message was not processed: client-supplied history, too many tokens, or nothing left after clean-up. | 400 or 413 |
| `error` | A check could not complete, so the request was stopped. No model text was returned. | 502 or 503 |

## Settings

The `harness:` section of `settings.yaml` lists every adjustable value with its range. A value outside its range is replaced by the nearest bound, and the change is printed at startup and shown on the Runtime panel. `palisade harness show` prints the effective values. Settings are fingerprinted in `manifest.lock` like the rest of the file, so a change needs `palisade install` to record it and appears in the audit trail.

## Testing

| Test | Where it runs | What it proves |
|---|---|---|
| `tests/test_harness.py` | Every CI run, every platform | Each layer on its own, and the full request path with model doubles, including every fail-closed branch. |
| `tests/test_harness_live.py` | CI job `harness-live`, against the pinned llama-server build (hash-checked) and a tiny generated model | Key enforcement, socket permissions, a hostile environment being dropped, the probe on a real vocabulary, port squatting refused, the real Guardian failing closed, and the startup path including the loopback fallback. |
| `palisade harness test` | On your installation, with the real models | Runs every case in `eval/harness_cases.yaml` through the full path, including cases that depend on model judgment (system-prompt extraction, direct injection, a request split across three messages). Writes `eval/harness-<time>.json` under the data folder, which the NIST benchmark reads for MEASURE-2.7. |

`palisade harness test` raises the rate limit for its own run only, and tags its audit records `source: harness-test` so reviewers can tell them apart. In service mode, stop the service first, as for `palisade eval`.

## Limits

- The harness enforces structure. Whether content is acceptable is still the guardian's judgment, and the guardian can be wrong.
- The canary catches verbatim or lightly transformed disclosure of the system prompt. A model that paraphrases its instructions will pass the canary check; the guardian's `prompt_injection` category is the other line of defense.
- Conversation screening covers the last few messages (three by default). A request spread across many more turns relies on the per-message checks.
- History is held in memory and is lost when Palisade restarts, by design.
- On Windows the model servers listen on loopback. The key keeps other accounts out, but a process running as an administrator can still read Palisade's memory, as with any local program.
