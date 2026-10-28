# BAYORA architecture review and implementation map

Source: `BAYORA_Product_Technical_Architecture_v2_Audit_Resolved.pdf`, version 2.0, 15 October 2026, 17 pages. This review uses the supplied document, including its corrected logical architecture diagram on PDF page 4. Section references below point to that source. The source is an engineering blueprint; its “Designed” controls are not implementation evidence.

## What BAYORA is

BAYORA is an AI application security evaluation platform. The Adversarial Engine runs scoped tests. The Defense Engine evaluates the customer's observable behavior. The Integrity/Validity engines assess BAYORA's own execution conditions. The platform does not replace customer defenses and cannot infer private target internals from a black-box response.

The output must keep four dimensions separate: harness integrity (`VALID`, `INVALID`, `UNVERIFIED`); target visibility (`BLACK-BOX`, `INSTRUMENTED`, `NOT ASSESSED`); defense outcome (`BLOCKED`, `PARTIAL`, `BYPASSED`, `INCONCLUSIVE`); and finding confidence. A successful attack does not itself invalidate the harness. A valid harness does not certify the target.

## Implementation delivered

This is a runnable, synthetic core-loop prototype. It is intentionally earlier than a deployable implementation of all phases in the document. It includes a Python package, CLI, FastAPI development control plane, serial persistent queue, short-lived local subprocess worker, five-category curated catalog, deterministic assessor, fixture metrics, immutable contracts, budgets, local evidence verification, reports and replay comparison.

It does not connect to live targets. `demo://safe`, `demo://vulnerable` and `demo://ambiguous` are deterministic in-process simulators inside the worker, not LLMs. They give predictable positive, negative and ambiguous controls. There are no API keys, external inference bills, live tools, customer code, or autonomous attack agents.

| Document requirement | Implemented behavior | Remaining gap |
|---|---|---|
| §1.3, §3.1 separate validity subjects | Independent report fields; deterministic three-state validity | Local process isolation and egress are UNKNOWN, so default runs are UNVERIFIED |
| §2.1 modular monolith | Separate Python modules and API/queue/worker commands | No UI, production control plane or service deployment |
| §2.3 immutable contract | Frozen Pydantic model; hash; expiry checked at submission and execution; strict target/catalog/budget scope | No image digest, protected authorization record or managed policy registry |
| §3.2 assurance levels | Canonical per-run hash chain, local manifest, report projection hash | Level 0 only; no independent signer, timestamp anchor or host-admin resistance |
| §3.3 canaries | Applicability and positive-control semantics; stateless demo reports NOT TESTED | No cross-session stateful target integration |
| §4.1 defense evaluation | Exact synthetic markers, structured block events and mock tool traces; ambiguous output is inconclusive | No general semantic judge; independent labeled benchmark and reviewer workflow remain |
| §4.3 attack categories | Instruction conflict, sensitive data, system exposure, RAG manipulation, mock tool misuse | One template per category, no adaptive generation or broad target-specific coverage |
| §5.1 worker | Fixed command, scrubbed environment, per-run subprocess, timeout/cancel and reap | A subprocess is NOT a container sandbox; constrained Docker launcher is not implemented |
| §5.2 authorization/SSRF | Only exact built-in target identifiers accepted; URLs rejected | Ownership proofs, pinned DNS/IP connections, egress proxy/firewall and bypass testing required before HTTP adapter |
| §6 privacy/evidence | No raw payload retention; metadata redacted before hashing; verification before export | SQLite is not an independently append-only store; no encrypted artifact vault or crypto-deletion |
| §7 replay | Comparable metadata, baseline-objective matching, repeated trial thresholds, no automatic closure with unverified harness | Real model changes and distributions cannot be measured with deterministic fixtures |
| §8 auth/API | Explicit development mode, scoped tester/auditor bearer tokens, read/queue/cancel/events/verify/export routes | No OIDC, organizations, membership CRUD, token revocation service or production RBAC |
| §9 workload | One active job across connections, at most 20 attempts, wall/output/total byte budgets, measured run duration | No throughput/cost scalability claim; token budgets are N/A without a model |
| §10 database | SQLite portable development queue with atomic claim and unique running-state constraint | Document selects PostgreSQL for deployed prototype; migrate before shared-host use |
| §11–12 release gates | Automated regression suite and CI definition | Infrastructure, operations and pilot gates have not been completed |

## Main design risks and decisions

1. **Do not claim proof from absence.** A response without a marker is inconclusive unless a structured controlled block is observable. A transport error is also inconclusive. Tool misuse requires traces; text claiming an action is not evidence that it happened.
2. **Keep execution trust explicit.** The bundled worker executes only trusted fixture code, but its OS network is not independently restricted. Source fingerprints record identity; they do not replace pinned containers. The code therefore never marks these infrastructure gates as passed.
3. **Make the evidence promise modest.** Hashes detect inconsistent edits, event reordering and truncation relative to the stored manifest. Someone who controls both records and manifest can rewrite them. The report hash also detects accidental changes to metrics and metadata; it is not a signature.
4. **Avoid sensitive collection.** This prototype assesses synthetic output in memory, then persists only verdicts, byte counts and rationale. That minimizes exposure but means an exported report cannot independently re-score the original response. Redaction is a fallback, not a universal secret detector.
5. **Do not overstate replay.** Reproduced means an objective recurred under comparable metadata. Not reproduced is not fixed. A target/version change produces INCONCLUSIVE in this conservative implementation and requires a new approved evaluation baseline. Automatic closure is unavailable for the unverified local harness.
6. **Treat fixture metrics as implementation checks.** The labeled examples measure whether deterministic rules behave as authored. They do not estimate real-world precision, recall, or vulnerability prevalence. Independent reviewers and a representative dataset remain necessary.
7. **Do not smuggle a network adapter past the prerequisites.** The next hosted-target milestone must include proof-of-control, authorization expiry, enforced destinations, per-connection DNS/IP policy, redirect handling, rate limits and cost reservations. Adding a bare `requests.post()` would bypass the architecture's central safety boundary.

## Audit finding coverage

| Audit finding | Delivered disposition |
|---|---|
| F-01 validity subject | Implemented separation and scoped wording |
| F-02 trust root | Level 0 only; stronger assurance deferred |
| F-03 canary assurance | NOT TESTED and positive-control semantics implemented |
| F-04 defense method | Deterministic assessor and fixture dataset; independent accuracy unmeasured |
| F-05 worker model | Local subprocess only; ephemeral container launcher still required |
| F-06 authorization/SSRF | External targets disabled; network controls still required |
| F-07 evidence/privacy | Sanitized chain and no raw artifacts; protected storage and retention automation pending |
| F-08 nondeterminism | Conservative repeat-trial comparison; fixtures do not model stochastic behavior |
| F-09 auth/data model | Small project-scoped dev API; full production identity model pending |
| F-10 model roles | No attacker/judge/target provider conflation; no external models selected |
| F-11 VM resources | Serial queue and attempt limits; VM not accessed or benchmarked |
| F-12 cost/scale | Measured local duration and bytes; zero model calls; no scale claims |
| F-13 secrets/TLS | No secrets required for CLI; scoped dev API credentials; no production TLS/encryption deployment |
| F-14 roadmap | Core loop first; remaining dependency order stated below |
| F-15 service boundaries | Modular package with separate worker process; no unnecessary services |
| F-16 development/deploy | Local install/test instructions and CI template; no cloud deployment performed |

## Next engineering milestones

1. Move the queue to PostgreSQL, add explicit organization/project entities, OIDC/JWT and a revocable scoped token registry. Add database permissions for the evidence append path.
2. Implement the separate narrow launcher: immutable allowed image, non-root user, dropped capabilities, seccomp, resource limits, read-only filesystem, bounded scratch, no API Docker socket, stop/reap/cleanup controls.
3. Implement target registration proof and the egress enforcement component. Prove negative cases for metadata, private IPv4/IPv6, redirects, rebinding and direct-egress bypass before enabling any hosted endpoint.
4. Add one HTTP adapter with real provider usage, explicit per-attempt and per-run token/cost reservation, unknown-usage handling and metadata capture. Verify the chosen provider's current testing terms at that point.
5. Add stateful canary trials only for observable supported paths, protected artifact handling if needed, scheduled retention, independent signing/anchoring, and independent detector/reviewer evaluation.
6. Benchmark the actual VM, run backup/restore and incident-stop exercises, then assess pilot readiness. The document's infrastructure baseline was not checked against a live cloud account.

## Implementation references

Framework usage was checked against the official FastAPI documentation: https://fastapi.tiangolo.com/advanced/events/ . Subprocess timeout/cleanup semantics were checked against the Python reference: https://docs.python.org/3/library/subprocess.html . These references support implementation mechanics, not BAYORA security certification.
