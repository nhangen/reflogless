param(
    [string]$DistribDir = "target/distrib",
    [string]$WorkDir = "$env:RUNNER_TEMP/reflogless-windows-signing"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$zip = Get-ChildItem -Path $DistribDir -Filter "reflogless-x86_64-pc-windows-msvc.zip" -File |
    Select-Object -First 1
if (-not $zip) {
    throw "Windows release archive not found in $DistribDir"
}

if (Test-Path $WorkDir) {
    Remove-Item -Path $WorkDir -Recurse -Force
}
New-Item -ItemType Directory -Path $WorkDir | Out-Null

Expand-Archive -Path $zip.FullName -DestinationPath $WorkDir -Force

$signables = @(Get-ChildItem -Path $WorkDir -Recurse -File -Include *.exe,*.dll)
if ($signables.Count -eq 0) {
    throw "No Windows binaries found to sign in $($zip.FullName)"
}

if ($env:GITHUB_OUTPUT) {
    "signing_folder=$WorkDir" >> $env:GITHUB_OUTPUT
    "zip_path=$($zip.FullName)" >> $env:GITHUB_OUTPUT
}

Write-Host "Prepared $($signables.Count) Windows binary/binaries for Authenticode signing:"
$signables | ForEach-Object { Write-Host "  $($_.FullName)" }
