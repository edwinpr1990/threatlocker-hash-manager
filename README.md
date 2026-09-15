# ThreatLocker Hash Manager

Local, single-operator Streamlit dashboard built around the tested portal API workflow.
No credentials are embedded. No application creation or policy changes are performed.

## v2 engine improvements

- Every file search includes the CSV's application ID, and every delete body carries that same ID.
- Durable groups of 256 deletion intentions are committed before sending requests; results commit
  in groups. SQLite still uses WAL and synchronous FULL. A crash can leave a group uncertain, not lost.
- Bulk matching joins each page's hashes against the indexed input instead of querying every hash separately.
- Pagination continues until an empty page and rejects file IDs repeated anywhere in the scan.
  Server pagination still needs stable ordering: do not edit the same application concurrently.
- Verification mode is independent of discovery. Auto uses selective reads for up to 1,000 targets,
  bulk above that. This is an explicit heuristic, not a guarantee of the fastest strategy.
- HTTP 429 reduces shared client concurrency and respects Retry-After. Failed or ambiguous deletion
  requests stop new submissions; POSTs are not automatically retried.
- Recovery rechecks original application IDs, organization, OS, file IDs, hashes, and hash-only type.
  Missing records become VerifiedAbsent; still-valid present records form a new confirmation plan.
- Local OS application locks coordinate workers started through either UI or CLI. They cannot
  prevent a different machine or portal user from editing the same application.

### Headless / externally scheduled worker

Provide authorization in the process environment variable `TL_AUTHORIZATION`, or enter it at the
hidden interactive prompt. Do not put tokens in command arguments or committed configuration.

```powershell
python cli.py --org YOUR-ORG-ID --csv C:/data/hashes.csv --run-dir C:/data/runs/new-run --mode Bulk --page-size 10000
python cli.py --org YOUR-ORG-ID --run-dir C:/data/runs/new-run --recover --execute --confirm-count 50000 --mode Bulk --page-size 10000
```

The first command is read-only. The second reconciles the saved plan and deletes ONLY if its
remaining count is exactly 50,000. Replace that count with your reviewed target count. For an
externally scheduled fresh run, use a unique run directory, --execute, and --confirm-count.
No schedule is installed automatically. Expired credentials still require a valid replacement.
Recovery is supported for v2 databases; start a fresh dry run for v1 audit files.
Recovery always scans the affected application(s) to catch a file ID whose hash changed.
For the packaged build, replace `python cli.py` with `ThreatLockerHashManager.exe --worker`.
Set `TL_AUTHORIZATION` in the worker's process environment; windowed worker diagnostics go to
`%LOCALAPPDATA%/ThreatLockerHashManager/startup.log`. Its exit code is nonzero on failure.

## Windows executable

Download the ZIP from this repository's GitHub Releases and extract the entire folder.
Run `ThreatLockerHashManager.exe`; Python is bundled. The packaged app uses localhost
port 8511 and stores run data under `%LOCALAPPDATA%/ThreatLockerHashManager`.
See RELEASE-NOTES-v1.1.0.md for startup, shutdown, and unsigned-executable notes.
See [PERFORMANCE.md](PERFORMANCE.md) for the live 100,000-record test and local million-row
probes, and [API-FINDINGS.md](API-FINDINGS.md) for observed portal behavior.

To build locally, run `Build-Windows.ps1` with 64-bit Python 3.11+ on Windows.
It runs the tests and creates a [PyInstaller one-folder bundle](https://pyinstaller.org/en/stable/operating-mode.html).
Keep the `_internal` directory with the executable; no user CSVs, credentials, or run logs are packaged.

## Start on Windows

Run `Start-Dashboard.ps1` from PowerShell. It creates an isolated `.venv` on first use,
installs the pinned requirements, and starts the dashboard at http://localhost:8510.
Python 3.11+ is required. Alternatively:

```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8510
```

Run commands from this directory so `.streamlit/config.toml` is loaded.
If first-time installation is interrupted, run `.venv/Scripts/python.exe -m pip install -r requirements.txt`.

## Workflow

1. Enter Organization ID, exact Authorization header value, API instance (`a`, `d`, etc.), and UserInstance.
2. Upload UTF-8 CSV with `ApplicationId,Hash,OsType` and optionally `RecordType`.
3. Choose Selective for a small subset of a huge application, or Bulk for large deletion lists.
4. Build a dry-run preview. This validates every application's ID, organization, and OS.
5. Review application names, counts, sample record IDs, and downloadable complete results.
6. Type `DELETE <exact count>` and execute. Stop prevents new requests, not already dispatched writes.
7. Review verified outcomes and save the CSV/JSON audit.

OS types supported: `1` Windows, `2` macOS. Hash values must be 32, 40, or 64 hex characters.
`RecordType` accepts `HASH`, `SHA256ONLY`, `SHA256`, or `SHA-256`; SHA256 requires 64 hex characters.
Exact matching checks the API's `hash`, `originalHash`, `sha256`, and `sha256Hash` fields,
as in the tested script. RecordType validates input; it does not override the returned record's type.
Only records with explicit `isHashOnly=true` are eligible. Duplicate input hashes are deduplicated
within an application. Multiple matching record IDs are all shown in the plan; review the count.
Missing hashes are skipped. Any malformed input blocks the entire run before deletion.

## Large runs and safety

- SQLite stores CSV rows, delete bodies, statuses, and durable dispatch intents in `runs/<id>`.
- Bulk discovery streams API pages and matches against an indexed on-disk CSV table.
- Selective mode queries hashes only inside their specified application, without a whole-app scan.
- At most the configured worker count is in flight. Six is the tested default; more is not necessarily faster.
- Only GETs retry transient errors. A failed/ambiguous POST stops further submission and triggers read-back verification.
- A preview expires after 30 minutes and is bound to its CSV and connection settings (or saved recovery scope).
- Execution revalidates all application metadata. Do not edit the same application concurrently.
- Verification checks dispatched file IDs are absent. Unlike the synthetic benchmark, the dashboard
  does not assert that unrelated application records are unchanged by other users.
- Results distinguish `Planned` (not sent), `Reserved` (durable group intent), `Dispatched` (outcome may be unknown),
  `Accepted`, `Uncertain`, `VerifiedAbsent`, and `StillPresent`. An absent record after a timeout
  is reported as absent, not as proof the POST returned success.
- Closing the browser does NOT stop a job. Stop in the dashboard. Terminating the server can leave
  uncertain writes; reconcile the saved v2 run before confirming its remaining targets. There is no blind replay.
- CSV upload itself and downloads use Streamlit memory (limit 512 MB); application records and
  pending futures are not all loaded into RAM. Million-row production performance is not certified.
- CSV input, hashes, and API deletion payloads persist locally. Protect `runs/` with normal Windows
  permissions and retain/delete these files according to your organization's policy.
- Authorization stays in process memory (including Streamlit session state); no token is written
  to run files or displayed in error responses. Restart the server to clear in-memory credentials.
- Bind to localhost only. This app has no login or multi-tenant isolation and is not for public hosting.

These are the portal endpoints observed in the existing tested scripts, not a guarantee of a stable
public API contract. Unexpected response shapes fail closed. Recheck compatibility after vendor changes.

## Tests

```powershell
python -m unittest discover -s tests -v
```

Automated tests use fake API responses: they do not delete live ThreatLocker records.
Streamlit's [fragment auto-rerun mechanism](https://docs.streamlit.io/develop/concepts/architecture/fragments)
updates the monitor independently; the deletion engine never calls Streamlit APIs from worker threads.
