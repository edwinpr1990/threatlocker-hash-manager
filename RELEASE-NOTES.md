# v1.0.0 — ThreatLocker Hash Manager

Windows x64 portable Streamlit application for application-scoped hash deletion.

## Run the Windows build

1. Download `ThreatLockerHashManager-v1.0.0-windows-x64.zip` and extract the entire ZIP.
2. Run `ThreatLockerHashManager.exe` inside the extracted folder. Keep `_internal` alongside it.
3. The dashboard opens in your browser at http://127.0.0.1:8511. No Python installation is needed.
4. Enter your own organization, authorization, and instance settings. Nothing runs until you build a preview and confirm deletion.

This is an unsigned executable; Windows or endpoint application control may block it.
Use your organization's normal review and approval process. Do not disable security controls.

The build is a portable folder, not a single-file installer. Python and dependencies are bundled.
API instance defaults to `d`; change it for your tenant. Audit data and startup diagnostics are
stored under `%LOCALAPPDATA%/ThreatLockerHashManager`. No authorization token is bundled.

Closing the browser does not shut down the executable. First stop any job in the dashboard and
wait for reconciliation, then end `ThreatLockerHashManager.exe` in Task Manager to stop the server.
Launch with `--port 8512` if the default port is occupied.

## Included

- CSV upload, Windows/macOS and SHA256 input validation.
- Application/organization/OS validation and required dry-run confirmation.
- Selective and bulk lookup; bounded parallel workers; read-back verification.
- SQLite audit storage and CSV/JSON result downloads.
- Source code, automated fake-API tests, and reproducible Windows build script.

No additional live deletions are performed as part of build testing. This initial release has not
been certified for million-record production workloads. Review README.md before live use.
