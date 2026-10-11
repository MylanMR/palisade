# Contributing

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements-dev.lock
python -m pytest tests/ -q
```

## Dependencies

`requirements.txt` lists what Palisade needs. `requirements.lock` and `requirements-dev.lock` record the exact versions and hashes that actually get installed, for every supported Python version and platform. Every install path uses the locks with `--require-hashes`, so pip refuses any package that does not match.

To change a dependency, edit `requirements.txt` (or `requirements-dev.txt`), then regenerate both locks with [uv](https://docs.astral.sh/uv/):

```bash
uv pip compile requirements.txt --universal --python-version 3.9 --generate-hashes -o requirements.lock
uv pip compile requirements.txt requirements-dev.txt --universal --python-version 3.9 --generate-hashes -o requirements-dev.lock
```

Review the diff of the lock files, not just the requirement files: every changed version and hash is code you are choosing to run. The development setup above should then use `pip install --require-hashes -r requirements-dev.lock`.

GitHub Actions in `.github/workflows/` are pinned to full commit SHAs. Dependabot proposes updates; check the release before merging one.

## Before opening a pull request

- `python -m pytest tests/ -q` passes.
- `python -m palisade benchmark` runs without error.
- New guardian behavior comes with eval cases in `eval/cases.jsonl`.
- Policy changes bump the `version` in `config/policy.yaml`.
- Any new NIST control mapping is added to `compliance/nist_ai_rmf/catalog.yaml` with a resolver in `benchmark.py`, or marked manual/out_of_scope with a reason.

## Scope discipline

The benchmark's value depends on honest scoping. Do not mark an organizational control `met` because a related mechanism exists. If the tool does not enforce it, it is `manual` or `out_of_scope` with a stated reason.
