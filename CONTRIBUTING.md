# Contributing

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/ -q
```

## Before opening a pull request

- `python -m pytest tests/ -q` passes.
- `python -m palisade benchmark` runs without error.
- New guardian behavior comes with eval cases in `eval/cases.jsonl`.
- Policy changes bump the `version` in `config/policy.yaml`.
- Any new NIST control mapping is added to `compliance/nist_ai_rmf/catalog.yaml` with a resolver in `benchmark.py`, or marked manual/out_of_scope with a reason.

## Scope discipline

The benchmark's value depends on honest scoping. Do not mark an organizational control `met` because a related mechanism exists. If the tool does not enforce it, it is `manual` or `out_of_scope` with a stated reason.
