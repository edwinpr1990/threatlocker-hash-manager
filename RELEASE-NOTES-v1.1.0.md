# v1.1.0 — Large-record performance and recovery

- Application-ID scope remains mandatory for every lookup and deletion.
- Durable intention/result batches retain SQLite FULL durability while reducing commits.
- Page-sized SQL joins accelerate bulk matching; stronger pagination checks detect overlapping IDs.
- Saved v2 runs can be reconciled and resumed after a new exact-count confirmation.
- Recovery scans original applications to detect changed hashes or non-hash-only rules.
- Independent verification strategy; shared 429 cooldown and concurrency reduction.
- Local application locks coordinate concurrent CLI/dashboard processes.
- Headless worker: `ThreatLockerHashManager.exe --worker ...` (requires TL_AUTHORIZATION in process environment).

Extract the entire Windows ZIP and keep `_internal` next to the executable. Double-click
`ThreatLockerHashManager.exe` for the dashboard at http://127.0.0.1:8511. Python is bundled.
Run data lives under `%LOCALAPPDATA%/ThreatLockerHashManager`; no credentials are bundled.
This executable is unsigned. Use your organization's normal approval process.

v1 audit files require a fresh dry run. v2 recovery is not blind replay: it queries ThreatLocker,
revalidates remaining targets, and requires confirmation. No schedule is installed automatically.
The Auto verification threshold is a heuristic, not a measured query-cost model.
There is no validated bulk-delete API in this release; deletes still use the verified file-by-ID endpoint.

Do not edit the same application from the portal or another machine while a job is running.
Closing the browser does not stop the worker. Stop submissions in the dashboard and let verification
finish before ending the process. Request acceptance alone is never treated as verified deletion.

See PERFORMANCE.md for measured test results and remaining limitations.
