param(
    [Parameter(Mandatory = $true)]
    [string]$SigningFolder,

    [Parameter(Mandatory = $true)]
    [string]$ZipPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $SigningFolder)) {
    throw "Signing folder not found: $SigningFolder"
}

$signables = @(Get-ChildItem -Path $SigningFolder -Recurse -File -Include *.exe,*.dll)
if ($signables.Count -eq 0) {
    throw "No signed Windows binaries found in $SigningFolder"
}

foreach ($file in $signables) {
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName
    if ($signature.Status -ne "Valid") {
        throw "Authenticode verification failed for $($file.FullName): $($signature.Status) $($signature.StatusMessage)"
    }
    Write-Host "Verified Authenticode signature: $($file.FullName)"
}

if (Test-Path $ZipPath) {
    Remove-Item -Path $ZipPath -Force
}

$archiveInputs = Join-Path $SigningFolder "*"
Compress-Archive -Path $archiveInputs -DestinationPath $ZipPath -Force

$hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumPath = "$ZipPath.sha256"
$checksumLine = "$hash *$(Split-Path -Path $ZipPath -Leaf)"
Set-Content -Path $checksumPath -Value $checksumLine -NoNewline -Encoding ascii

Write-Host "Repacked signed Windows archive: $ZipPath"
Write-Host "Updated checksum: $checksumPath"
