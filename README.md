# BAYORA — Python AI red-team prototype

A runnable implementation of the **synthetic core loop** in the supplied BAYORA v2 architecture. It tests bundled safe, vulnerable and ambiguous simulators, assesses outcomes, verifies sanitized evidence, and exports an evaluation passport.

**Scope:** local development, synthetic data, no external endpoints, no real LLM calls. This is a working starting point, not the complete production platform described in the PDF. The detailed review and requirement map are in [docs/ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md).

## Quick start

Requires Python 3.11 or later. From this folder:

```bash
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m bayora demo --target vulnerable --out output/vulnerable
python -m bayora demo --target safe --out output/safe
python -m bayora verify output/vulnerable/report.json
python -m pytest -q
```

Open `output/vulnerable/report.html` in your browser. Pre-generated reports are included in `examples/safe/`, `examples/vulnerable/`, and `examples/ambiguous/`.

Default runs use five categories × three trials = 15 attempts. The vulnerable fixture produces 15 BYPASSED outcomes; the safe fixture produces 15 BLOCKED outcomes; the ambiguous fixture produces 15 INCONCLUSIVE outcomes. These are controlled test fixtures, not measured LLM security results. All three local runs correctly report **harness integrity: UNVERIFIED** because container isolation and network enforcement have not been verified.

## What is included

- Frozen, versioned contracts with project scope, expiry, catalog scope and attempt/time/byte limits.
- Five curated attack templates: prompt injection, synthetic data leakage, system-instruction exposure, RAG manipulation and mock tool misuse.
- Separate deterministic Defense and Integrity engines; human-review flags on candidate findings.
- Persistent SQLite queue with one running job; short-lived trusted subprocess execution; cancellation and timeout cleanup.
- Canonical redacted event hash chain, manifest and report projection checks at **Level 0**.
- Static HTML and JSON passports, replay comparison, descriptive trial intervals, and a 25-case detector regression corpus.
- FastAPI development API with project-scoped tester/auditor tokens, plus regression tests and GitHub Actions template.

No real email, database mutation, financial operation, filesystem tool, or customer-supplied code is executed by attacks. Synthetic secrets are provisioned privately in fixtures rather than supplied verbatim in attack prompts (except the deliberately untrusted RAG document).

## Contract and budgets

Generate a fresh contract so the authorization window has not expired:

```bash
python -m bayora contract --target vulnerable > contract.json
python -m bayora run contract.json --out output/custom
```

JSON fields are strict; unknown keys, external targets and removed mandatory gates are rejected. The maximum is 20 planned attempts and one concurrent run. The parent enforces wall-clock timeout and reaps the child. The fixture worker checks input/output and total byte limits. It reserves the configured maximum output allowance before each attempt. Byte accounting is fixture input and serialized output, not model token accounting. Cost is exactly zero because no provider is called. Per-token model budgets are intentionally unavailable until a real provider adapter and trusted usage accounting exist.

This worker is a trusted Python subprocess, **not a security sandbox**. It does not execute arbitrary code or accept arbitrary commands. Its bounded output assumption relies on trusted bundled source, not an OS output-stream limit. The source digest records code identity; it is not a container image digest.

## API workflow

Install the `api` extra if you did not install `dev`. Bind the service only to localhost. It refuses to start without explicit development mode and configured tokens. The API never launches workers itself and has no Docker integration.

For macOS/Linux, create a fresh development token in the environment without putting its value in command history:

```bash
export BAYORA_ENV=development
export BAYORA_DB="$PWD/data/bayora.sqlite3"
export BAYORA_DEV_TOKENS="$(python -c 'import json,secrets; print(json.dumps([{"token":secrets.token_urlsafe(32),"project":"demo","role":"tester"}]))')"
python -m uvicorn bayora.api:create_app --factory --host 127.0.0.1 --port 8000
```

Use `http://127.0.0.1:8000/docs` to inspect the API. Configure the Bearer token from your local environment in your client; do not commit or share it. For Windows, set the equivalent variables with `$env:NAME` in PowerShell. These development bearer tokens are not OIDC or production credentials.

In another terminal, from the same folder (same database path):

```bash
python -m bayora worker
```

Submit a JSON contract to `POST /api/v1/test-runs` with `Authorization: Bearer <your-token>`. Read status at `GET /api/v1/test-runs/{run_id}`. Stop the worker with Ctrl+C. `worker --once` processes at most one queued run. Pending jobs survive process exit. There is no automatic worker lease recovery: after verifying all workers have stopped, `python -m bayora recover --workers-stopped` marks abandoned running jobs FAILED. Interrupted runs without a finalized report remain unverified and do not receive a passport.

| Route | Access / purpose |
|---|---|
| `GET /health` | Public, minimal health status |
| `GET /api/v1/targets` | Authenticated, built-in fixtures only |
| `POST /api/v1/contracts/validate` | Tester, validate project-scoped contract |
| `POST /api/v1/test-runs` | Tester, queue run |
| `GET /api/v1/test-runs` | Tester/auditor, own project only |
| `GET /api/v1/test-runs/{id}` | Own-project run |
| `POST /api/v1/test-runs/{id}/cancel` | Tester, request cancellation |
| `GET /api/v1/test-runs/{id}/events` | Own-project sanitized events |
| `GET /api/v1/passports/{id}` | Verified report |
| `GET /api/v1/reports/{id}/export` | Verified JSON report |
| `POST /api/v1/evidence/{id}/verify` | Local consistency result |

This subset does not implement organization/project creation, hosted target registration, finding CRUD, or the full production API. Replay is available through the CLI comparison below.

## Replay and detector checks

```bash
python -m bayora demo --target vulnerable --out output/replay
python -m bayora compare output/vulnerable/report.json output/replay/report.json
python -m bayora.evaluate examples/detector_dataset.json --out output/detector-metrics.json
```

Compare independent runs of the same target and protocol. A matching failure gives REPRODUCED. No failure alone is not proof of a fix. Changed target/version metadata gives INCONCLUSIVE. LIKELY FIXED requires the predeclared minimum trial count per failing category, all relevant outcomes blocked, comparable conditions and valid harnesses; local demo runs cannot meet that last gate. A single replay never closes a high-severity finding.

The labeled corpus is a developer-authored rule regression set. Its accuracy is not a real-model benchmark, and inter-reviewer disagreement has not been measured. Confidence intervals in reports are descriptive only for the deterministic fixtures.

## Evidence and data lifecycle

Reports do not store raw prompts, responses or synthetic secret values. Only sanitized outcome metadata is hashed. This means independent re-scoring of raw responses is unavailable. The evidence chain catches inconsistent edits, reordered events and truncation relative to its local manifest. The report digest binds report fields to that same manifest. A privileged host user can rewrite everything consistently; Level 0 is not tamper-proof and does not provide independent attestation.

`retention_days` records intended policy; automated expiry/deletion is **not implemented** in this prototype. Keep only synthetic data. Remove local SQLite files and report folders when finished; secure deletion, encrypted artifacts, append-only database roles, and compliance retention are not claimed. No raw artifact store exists, so there is no encrypted raw replay or tombstone workflow.

## Project structure

```text
bayora/models.py      validated immutable contract
bayora/catalog.py     curated scenarios
bayora/targets.py     bundled controlled simulators
bayora/defense.py     outcome classification
bayora/integrity.py   validity and canary semantics
bayora/evidence.py    canonical redacted hash chain
bayora/store.py       serial persistent queue
bayora/worker.py      trusted bounded fixture execution
bayora/runner.py      process lifecycle, passport, replay
bayora/reporting.py   HTML/JSON export
bayora/api.py         local development control plane
bayora/cli.py         command-line entry point
bayora/evaluate.py    labeled detector regression metrics
```

See [docs/VALIDATION.md](docs/VALIDATION.md) for tested behavior and `requirements-tested.txt` for the dependency versions used. See [docs/ARCHITECTURE_REVIEW.md](docs/ARCHITECTURE_REVIEW.md) for all implementation gaps and next milestones. PostgreSQL, a constrained ephemeral container launcher, enforced egress, target ownership proof, OIDC, protected signing and pilot operations are required before hosted/customer testing. No cloud account or VM was accessed or deployed to.
