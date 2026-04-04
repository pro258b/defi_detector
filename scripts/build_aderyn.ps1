param(
    [switch]$Release = $true
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$aderynRoot = Join-Path $projectRoot "external\aderyn"

if (-not (Test-Path $aderynRoot)) {
    throw "Pinned Aderyn dependency not found at $aderynRoot"
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Rust toolchain not found. Installing rustup via winget..."
    winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if (Test-Path $cargoBin) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

$profile = if ($Release) { "release" } else { "dev" }

Push-Location $aderynRoot
try {
    if ($Release) {
        cargo build --release
    } else {
        cargo build
    }
} finally {
    Pop-Location
}

$binaryName = if ($IsWindows) { "aderyn.exe" } else { "aderyn" }
$binaryPath = Join-Path $aderynRoot "target\$profile\$binaryName"

if (-not (Test-Path $binaryPath)) {
    throw "Aderyn build completed but binary was not found at $binaryPath"
}

Write-Host "Built pinned Aderyn binary at $binaryPath"
