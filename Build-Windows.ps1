$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (!(Test-Path -LiteralPath '.build-venv/Scripts/python.exe')) {
    python -m venv .build-venv
    if ($LASTEXITCODE -ne 0) { throw 'Build environment creation failed.' }
}
& .build-venv/Scripts/python.exe -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw 'Build dependency installation failed.' }
& .build-venv/Scripts/python.exe -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
& .build-venv/Scripts/python.exe -m PyInstaller --noconfirm --onedir --windowed --name ThreatLockerHashManager --add-data 'app.py:.' --add-data '.streamlit/config.toml:.streamlit' --hidden-import engine --collect-all streamlit --recursive-copy-metadata streamlit --collect-all requests launcher.py
if ($LASTEXITCODE -ne 0) { throw 'Executable build failed.' }
Write-Host 'Build ready: dist/ThreatLockerHashManager/ThreatLockerHashManager.exe'
