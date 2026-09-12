# ThreatLocker Hash Manager

Local, single-operator Streamlit dashboard built around the tested portal API workflow.
No credentials are embedded. No application creation or policy changes are performed.

## Windows executable

Download the ZIP from this repository's GitHub Releases and extract the entire folder.
Run `ThreatLockerHashManager.exe`; Python is bundled. The packaged app uses localhost
port 8511 and stores run data under `%LOCALAPPDATA%/ThreatLockerHashManager`.
See RELEASE-NOTES.md for startup, shutdown, and unsigned-executable notes.

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
- A preview expires after 30 minutes and is bound to its CSV and connection settings.
- Execution revalidates all application metadata. Do not edit the same application concurrently.
- Verification checks dispatched file IDs are absent. Unlike the synthetic benchmark, the dashboard
  does not assert that unrelated application records are unchanged by other users.
- Results distinguish `Planned` (not sent), `Dispatched` (intent logged, outcome may be unknown),
  `Accepted`, `Uncertain`, `VerifiedAbsent`, and `StillPresent`. An absent record after a timeout
  is reported as absent, not as proof the POST returned success.
- Closing the browser does NOT stop a job. Stop in the dashboard. Terminating the server can leave
  uncertain writes; inspect the audit and run a fresh dry run. There is no automatic resume/replay.
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
