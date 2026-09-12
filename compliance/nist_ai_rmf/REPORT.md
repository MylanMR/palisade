# NIST AI RMF Benchmark: Palisade

Framework: NIST.AI.100-1 (AI RMF 1.0) with NIST.AI.600-1 (Generative AI Profile)  
Verified against https://www.nist.gov/itl/ai-risk-management-framework on 2026-09-06  
Catalog version 1.0.0, generated 2026-09-12T03:13:01Z

## Summary

- In-scope controls scored: **22**
- In-scope coverage: **100%**
- Coverage by function: GOVERN 100%, MAP 100%, MEASURE 100%, MANAGE 100%
- Manual attestations required: **1**
- GenAI-profile risks scored: **10** at **65%** (2 out of scope)

Coverage is computed only over controls a single desktop runtime control can bear on. Organizational controls are listed as manual attestations, not counted as met.

## Controls

| Control | Fn | Method | Status | Evidence |
|---------|----|--------|--------|----------|
| GOVERN-1.1 | GOVERN | manual | manual_attestation_required | Palisade documents the enforced policy and its provenance, but mapping to the operator's specific legal obligations is an organizational task. |
| GOVERN-1.2 | GOVERN | auto | met | policy.local.yaml with categories |
| GOVERN-1.4 | GOVERN | auto | met | policy version 1.0.0 |
| GOVERN-1.5 | GOVERN | auto | met | 1 audit file(s) on disk |
| GOVERN-1.6 | GOVERN | auto | met | manifest.lock sections present: ['config', 'llama_cpp', 'models'] |
| GOVERN-4.1 | GOVERN | auto | met | manifest.lock sections present: ['config', 'llama_cpp', 'models'] |
| GOVERN-6.1 | GOVERN | auto | met | 5/5 models document lab+license+repo |
| MAP-1.1 | MAP | auto | met | docs/ARCHITECTURE.md present |
| MAP-2.3 | MAP | auto | met | docs/ARCHITECTURE.md present |
| MAP-3.4 | MAP | auto | met | check_output=True |
| MAP-4.1 | MAP | auto | met | 5/5 models document lab+license+repo |
| MEASURE-1.1 | MEASURE | auto | met | eval command present; 12 labeled cases |
| MEASURE-2.3 | MEASURE | auto | met | 1 eval report(s) retained |
| MEASURE-2.6 | MEASURE | auto | met | input=True output=True |
| MEASURE-2.7 | MEASURE | auto | met | policy category 'prompt_injection' present |
| MEASURE-2.8 | MEASURE | auto | met | record carries ['base_model', 'guardian_model', 'manifest_hash', 'policy_version'] |
| MEASURE-2.11 | MEASURE | auto | met | policy category 'hate_harassment' present |
| MEASURE-4.2 | MEASURE | auto | met | 1 eval report(s) retained |
| MANAGE-1.2 | MANAGE | auto | met | actions in policy: ['block', 'flag'] |
| MANAGE-2.3 | MANAGE | auto | met | chain intact over 1 records |
| MANAGE-2.4 | MANAGE | auto | met | actions in policy: ['block', 'flag'] |
| MANAGE-4.1 | MANAGE | auto | met | 1 audit file(s) on disk |
| MANAGE-4.3 | MANAGE | auto | met | retain_content=hashes (full available for incident review) |

## GenAI Profile risks (NIST.AI.600-1)

| Risk | Status | Note |
|------|--------|------|
| GAI-CBRN CBRN information or capabilities | met |  |
| GAI-CONFAB Confabulation (hallucination) | not_met | Guardrails do not measure factual accuracy. Use retrieval and separate eval; out of this control's scope. |
| GAI-DANGER Dangerous, violent, or hateful content | met |  |
| GAI-DATA-PRIV Data privacy | partial | A privacy_pii category flags PII-seeking requests; it does not prevent training-data leakage. |
| GAI-HARM-BIAS Harmful bias or homogenization | partial |  |
| GAI-OBSCENE Obscene / CSAM | met |  |
| GAI-CYBER Information security (offensive cyber uplift) | met |  |
| GAI-DEEPFAKE Harmful synthetic content / deepfakes | out_of_scope | Text-only stack; no image/audio generation to govern. |
| GAI-HUMAN-AI Harmful human-AI interaction / overreliance | partial | Refusals and flags exist; overreliance mitigation is a UX/organizational concern. |
| GAI-IP Intellectual property | not_met | Not screened by the default policy. Add a category and eval cases if in scope for the deployment. |
| GAI-ENV Environmental impact | out_of_scope | Local single-user inference; addressed by hardware choice, not a runtime control. |
| GAI-VALUE-CHAIN Value chain and component integration | met |  |

## Scope statement

This benchmark scores Palisade as a runtime control. A `met` status means the system provides the mechanism the subcategory calls for, evidenced by the artifact named. It is not an authorization or a certification; an accrediting authority owns that decision. Manual controls require human attestation with evidence.