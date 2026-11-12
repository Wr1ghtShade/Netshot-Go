# Build netshot into dist\.
#   .\build.ps1            Windows exe  -> dist\netshot.exe
#   .\build.ps1 -Linux     also Linux   -> dist\netshot-linux
#   .\build.ps1 -Icon      regenerate the icon before building
param([switch]$Linux, [switch]$Icon)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if ($Icon -or -not (Test-Path cmd\netshot\rsrc_windows_amd64.syso)) {
    go run ./tools/mkicon
}

New-Item -ItemType Directory -Force dist | Out-Null
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags "-s -w" -o dist\netshot.exe ./cmd/netshot
if ($LASTEXITCODE) { exit $LASTEXITCODE }
Write-Host "dist\netshot.exe"

if ($Linux) {
    $env:GOOS = "linux"; $env:GOARCH = "amd64"
    go build -ldflags "-s -w" -o dist\netshot-linux ./cmd/netshot
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
    Write-Host "dist\netshot-linux"
}
Remove-Item Env:GOOS, Env:GOARCH
