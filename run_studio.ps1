$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot
$env:PYTHONPATH = Join-Path $ProjectRoot "src"
if (Get-Command py -ErrorAction SilentlyContinue) {
    py -m kyojitsu studio --host 127.0.0.1 --port 8765 --runs-dir runs
} else {
    python -m kyojitsu studio --host 127.0.0.1 --port 8765 --runs-dir runs
}
