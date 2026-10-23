# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue.

Use GitHub's private reporting: open the repository's **Security** tab and select **Report a vulnerability**. Only the maintainer can see the report.

Include:

- what you found and which version (`palisade doctor` prints it)
- the steps or configuration needed to reproduce it
- what an attacker could achieve, and what access they need first (local account, network access, administrator)

Palisade is maintained by one person. Reports are handled on a best-effort basis, with the aim of acknowledging within seven days and agreeing a disclosure timeline with you before anything is made public. There is no bug bounty.

## Supported versions

Only the latest release receives security fixes. Upgrade before reporting if you can.

## What counts as a vulnerability

Palisade makes specific security claims. A way to break any of them is a vulnerability:

- **Screening cannot be skipped.** A way to get a message to the assistant, or an answer to the screen, without the guardian check that the settings call for.
- **The harness holds.** A way to get a chat-template control token, a client-written conversation turn, or text over the token limit to a model; to reach a model server without going through Palisade; or to get model text returned after a check failed or could not complete.
- **Decisions are made on the server.** A way for the browser or an API client to change a threshold, policy, verdict, or audit record.
- **Authentication holds.** A way to use `/api/*` without the session token, or `/api/review/*` without the reviewer token.
- **The audit log shows tampering.** A way to alter, remove, or reorder records so that both `palisade audit verify` and `palisade audit check-anchor` (against an anchor taken beforehand) still pass.
- **Service-mode permissions hold.** A way for the service account to modify its code, config, policy, models, or `manifest.lock`, or for an account outside `palisade-audit` to read audit data or the reviewer token, on a system installed with the provided installers.
- **Supply-chain checks hold.** A way to get a model, model-server binary, or Python package installed that does not match its published hash or `requirements.lock`, without an error.
- **Installers.** A way to make a released installer, or the setup job it registers, run code or trust a file that does not match its signature or published hash, or to give the service account write access to its own code, models, settings, or fingerprints.
- **Local-only by default.** A way to make a default installation reachable from another machine, or to bypass the startup refusal to bind to a network address.
- **Web issues.** Script injection in either page, path traversal through the static file route, or similar.

## What is a known limitation, not a vulnerability

These are documented in the README under "What Palisade does not do." Reports about them are welcome as ordinary issues, but they are not handled as security reports:

- **The guardian misclassifying content.** It is a classifier and makes mistakes in both directions. A prompt it fails to block is a guardian accuracy problem; please open an issue with the prompt, ideally as a case for `eval/cases.jsonl`. It becomes a vulnerability only if the code causes the check to be skipped.
- **An administrator or root altering files.** Administrators can always reach the data. The design makes that deliberate and detectable, not impossible. It becomes a vulnerability only if the alteration goes undetected by the checks listed above.
- **What the assistant model knows.** Blocking an answer does not remove knowledge from the model's weights.
- **Deployments that set `allow_remote: true`.** That setting exists for operators who add their own encryption and authentication in front of Palisade, and Palisade warns when it is used.

## Security design

- `docs/ARCHITECTURE.md`: request flow and threat model
- `docs/HARNESS.md`: the fixed rules around every model call
- `docs/AUDIT-REVIEW.md`: the audit chain, anchors, roles, and NIST SP 800-53 mapping
- `docs/SERVICE-INSTALL.md`: exactly what each installer creates, and how it was verified
- `packaging/SIGNING.md`: how releases are signed, and how to verify a download
