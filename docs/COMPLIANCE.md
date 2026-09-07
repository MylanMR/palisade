# Compliance

This document explains what Palisade produces for an assessor and how its behavior maps to a recognized framework. It is written to be read alongside the running system, not as a substitute for an organization's own authorization process.

## What is enforceable and reviewable

The enforceable artifact is `config/policy.yaml`. It is version-controlled, it has stable category identifiers, and each category names an action and a scope. Nothing about the policy lives in model weights or in prose, so an assessor reviews a file rather than inferring behavior.

The public repository ships a generic example policy. An operator's real, tuned policy is kept in `config/policy.local.yaml`, which is excluded from version control, and Palisade enforces it in preference to the example. This keeps sensitive rule text out of a public repo without weakening the audit trail: `manifest.lock` records the hash of whichever policy is in force, and every audit record carries the policy version, so a decision is still tied to the exact policy that produced it. For an assessment, the operator provides the real policy file directly rather than through the public repo.

The reviewable evidence is three things an assessor can inspect directly:

1. The policy file and its version number.
2. The audit log, whose integrity `palisade verify` confirms.
3. The eval report from `palisade eval`, which records precision and recall against a labeled set, the threshold, the guardian model, and the manifest hash under which it was measured.

Model weights are opaque and are not offered as evidence. The evidence is the policy, the measured behavior against it, and the tamper-evident record of decisions.

## Policy structure

Each category carries:

- `id`: a stable identifier used in reports and audit records.
- `action`: `block`, `flag`, or `allow`.
- `applies_to`: `input`, `output`, or both.
- `guardian_text`: the plain-language rule the classifier reads.

Because the identifiers are stable, an audit record from six months ago and one from today refer to the same category by the same name, even if the wording of `guardian_text` was refined in between. The policy `version` field and the per-record `policy_version` let an assessor tell which wording was in force for any given decision.

## NIST AI RMF benchmark

The crosswalk below is also a runnable benchmark. `compliance/nist_ai_rmf/catalog.yaml` is a machine-readable control catalog, verified against the NIST AI RMF page (framework NIST.AI.100-1 with the NIST.AI.600-1 GenAI Profile), and `python -m palisade benchmark` scores the actual installation against it, writing `compliance/nist_ai_rmf/REPORT.md` and a JSON report under `data/compliance/`.

The benchmark is deliberately honest about scope. Palisade is one runtime control on one desktop system, so organizational subcategories (workforce, legal obligations, third-party governance) are marked as manual attestations rather than auto-passed, and GenAI-profile risks the stack does not address (confabulation, intellectual property) or cannot address as a text-only local tool (deepfakes, environmental impact) are scored out of scope rather than counted as met. Each auto-scored control records the artifact that justifies its status, so the score itself is auditable.

Coverage is state-dependent by design. Before install it reads lower because `manifest.lock`, audit records, and eval reports do not exist yet; after `install`, `run`, and `eval` have produced those artifacts, in-scope coverage reaches full. That movement is the point: the number reflects the real state of the deployed system, not a static claim.

Note on framework currency: AI RMF 1.0 is under revision through the White House AI Action Plan, and a Critical Infrastructure Profile concept note was released in April 2026. AI RMF 2.0 is not yet published. When it lands, update `catalog.yaml`; the benchmark engine does not change.

The crosswalk, function by function:

Palisade is a runtime control. It touches the MANAGE and MEASURE functions of the NIST AI Risk Management Framework most directly, and supports GOVERN and MAP through its configuration and documentation.

| NIST AI RMF | Subcategory intent | How Palisade addresses it |
|-------------|--------------------|---------------------------|
| GOVERN 1.1 | Policies are documented and version-controlled | `config/policy.yaml` is the policy, under version control, hashed into `manifest.lock`. |
| GOVERN 4.1 | Mechanisms to inventory and track AI components | `manifest.lock` fingerprints the binary, both models, and all config; `doctor` reports drift. |
| MAP 2.3 | System requirements and constraints are defined | `docs/ARCHITECTURE.md` states the deployment shape, hardware bounds, and threat model. |
| MEASURE 2.6 | AI system is evaluated for safety | `palisade eval` produces precision and recall against a labeled set, saved with provenance. |
| MEASURE 2.7 | Security and resilience are evaluated | Prompt-injection category plus the manifest-verification gate on startup. |
| MEASURE 4.2 | Measurement results are documented | Each eval run writes a timestamped JSON report under `data/eval/`. |
| MANAGE 2.3 | Mechanisms to sustain and log system behavior | The hash-chained audit log records every decision with model and policy version. |
| MANAGE 4.1 | Post-deployment monitoring | Flagged records mark exchanges for review without blocking; the log is the monitoring surface. |

This is a crosswalk, not a certification. It shows where the control contributes; an authorization decision rests with the accrediting authority.

## Audit evidence

Each record answers: what was decided, by which models, under which policy version, against which binary and weights, and when. The prompt and response are stored as SHA-256 by default (`retain_content: hashes`), which keeps the log small and avoids retaining user content while still proving that a specific input produced a specific decision. For incident review you can set `retain_content: full` to store the text as well; treat that log as sensitive because it then contains the conversation.

Chain integrity is the property that makes the log evidentiary. `palisade verify` walks every record and confirms that each one's hash still follows from its predecessor. A broken chain names the first record that fails, so tampering is localized. Ship the head hash off-box periodically so that a full in-place rewrite is also detectable.

## Calibration

The guardian threshold defaults to 0.5 on the probability of a policy violation. It is a dial, not a constant. To calibrate:

1. Build a labeled set in `eval/cases.jsonl` that reflects your real traffic and your real hazards. The shipped file is a starting skeleton, not a sufficient test set.
2. Run `palisade eval` and read precision and recall.
3. Lower the threshold to raise recall (catch more, block more benign traffic) or raise it to raise precision (block less, miss more). The right point depends on which failure is more costly for your deployment.
4. For high-severity categories where a miss is unacceptable, prefer an ensemble of two guardians over pushing the threshold so low that benign traffic is heavily over-blocked. See `docs/MODELS.md`.

Record the threshold you chose and the eval report that justified it. Both are part of the compliance package, because a guardrail without a measured operating point is an assertion rather than a control.

## Limits worth stating plainly

Guardrails constrain behavior; they do not remove capability from the assistant's weights. The audit log is tamper-evident, not tamper-proof, against a privileged local attacker. The guardian is a classifier and will make errors, which is why its error rate is measured and reported rather than assumed to be zero. Stating these limits is part of an honest control description, and an assessor will trust the package more for their being present.
