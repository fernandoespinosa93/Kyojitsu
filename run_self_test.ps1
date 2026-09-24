$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:PYTHONPATH = Join-Path $PSScriptRoot "src"
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -m unittest discover -s tests -q
} else {
    & python -m unittest discover -s tests -q
}
exit $LASTEXITCODE
