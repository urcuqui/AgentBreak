# Run the full demo non-interactively. Windows PowerShell.
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $PSScriptRoot
Set-Location $here

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}
. .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip | Out-Null
python -m pip install -e . | Out-Null

python -m hacking_ai_agents.cli full-demo --no-pause @args
