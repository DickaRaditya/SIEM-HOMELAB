param(
    [ValidateSet('setup','start','stop','status','test','rule-test','credentials','logs','validate')]
    [string]$Action = 'status'
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Python 3.10+ is required. Install Python, then reopen PowerShell.'
}
& python (Join-Path $PSScriptRoot 'scripts/lab.py') $Action
exit $LASTEXITCODE
