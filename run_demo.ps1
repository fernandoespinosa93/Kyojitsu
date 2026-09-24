$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot
$env:PYTHONPATH = Join-Path $ProjectRoot "src"
if (Get-Command py -ErrorAction SilentlyContinue) {
    py -m kyojitsu run-campaign --campaign examples/campaign_fixture.json --output runs/demo
} else {
    python -m kyojitsu run-campaign --campaign examples/campaign_fixture.json --output runs/demo
}
Start-Process (Join-Path $ProjectRoot "runs/demo/report.html")
