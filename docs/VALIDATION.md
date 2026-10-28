# Validation record

Validated in the delivery environment on Python 3.12. Dependency versions are recorded in `requirements-tested.txt`. The project supports Python 3.11+ by declaration; the provided CI matrix has not run on GitHub in this session.

- Automated suite: **44 tests passed**.
- Safe simulator: 15/15 BLOCKED.
- Vulnerable simulator: 15/15 BYPASSED, candidate findings pending human review.
- Ambiguous simulator: 15/15 INCONCLUSIVE.
- All three sample runs: harness UNVERIFIED, fixture visibility INSTRUMENTED, Level 0 consistency only.
- Labeled detector regression corpus: 25/25 expected labels matched. This is authored fixture coverage, not independent model accuracy measurement.
- Sample vulnerable report: evidence and report projection verification passed.
- Package editable installation: checked separately from source imports.

Tests exercise contract expiry/scope/budget rejection, frozen contract behavior, all three validity states, refusal-plus-leak detection, absent tool traces, partial mock action outcomes, canary applicability and controls, redaction-before-hash, changed/reordered/truncated evidence, altered report fields, replay comparability, queue cancellation, active-job serialization, budget violations, active cancellation, child timeout/reaping, API authentication, auditor restrictions and cross-project denial.

One upstream development-test warning was observed: Starlette's TestClient deprecates its httpx path in favor of httpx2. Tests passed; this does not establish compatibility with future dependency releases. The tested-version file allows recreating this environment.

Not validated: real LLM behavior, external HTTP targets, cloud deployment, Docker/OS isolation, enforced egress, DNS/redirect controls, production OIDC, independent evidence signing, encrypted raw artifacts, scheduled retention, legal/compliance controls, multi-host scaling or disaster recovery.
