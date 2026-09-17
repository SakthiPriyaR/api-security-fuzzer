param(
    [Parameter(Mandatory = $true)][string]$TokenA,
    [Parameter(Mandatory = $true)][string]$ResourceIdA,
    [Parameter(Mandatory = $true)][string]$TokenB,
    [Parameter(Mandatory = $true)][string]$ResourceIdB,
    [string]$ResourceIdsB = "{}",
    [string]$BaseUrl = "http://localhost:8888",
    [string]$CrApiRef = "develop"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$reportsDir = Join-Path $repoRoot "reports"
New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
$specPath = Join-Path $reportsDir "crapi-openapi-spec.json"
$reportPrefix = Join-Path $reportsDir "crapi-validation"
$specUrl = "https://raw.githubusercontent.com/OWASP/crAPI/$CrApiRef/openapi-spec/crapi-openapi-spec.json"

Write-Host "Downloading OWASP crAPI OpenAPI spec ($CrApiRef)..."
Invoke-WebRequest -Uri $specUrl -OutFile $specPath

Write-Host "Running conservative read-only validation against $BaseUrl"
python -m fuzzer.cli `
    --spec $specPath `
    --base-url $BaseUrl `
    --token-a $TokenA --user-id-a $ResourceIdA `
    --token-b $TokenB --user-id-b $ResourceIdB `
    --resource-ids-b $ResourceIdsB `
    --safe-read-only `
    --skip mass_assignment `
    --out $reportPrefix `
    --fail-on never

if ($LASTEXITCODE -ne 0) {
    throw "Scanner failed with exit code $LASTEXITCODE"
}

Write-Host "Reports written to $reportPrefix.json and $reportPrefix.html"
Write-Host "Record the exact crAPI commit, account setup, resource IDs, and manual ground-truth review with these reports."
