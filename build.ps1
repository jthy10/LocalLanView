# Windows build script. Produces the same reproducible binaries as `make dist`.
#   .\build.ps1            build for this machine
#   .\build.ps1 -Dist      cross-compile every target into .\dist
param([switch]$Dist, [string]$Version)

$ErrorActionPreference = "Stop"
if (-not $Version) {
    $Version = (git describe --tags --always --dirty 2>$null)
    if (-not $Version) { $Version = "dev" }
}
$env:CGO_ENABLED = "0"
$ldflags = "-s -w -buildid= -X main.version=$Version"

if (-not $Dist) {
    go build -trimpath -buildvcs=false -ldflags $ldflags -o LocalLanView.exe ./cmd/locallanview
    exit $LASTEXITCODE
}

Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory dist | Out-Null
$targets = "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"
foreach ($t in $targets) {
    $os, $arch = $t.Split("/")
    $ext = if ($os -eq "windows") { ".exe" } else { "" }
    Write-Host "building $os/$arch"
    $env:GOOS = $os; $env:GOARCH = $arch
    go build -trimpath -buildvcs=false -ldflags $ldflags -o "dist/LocalLanView-$Version-$os-$arch$ext" ./cmd/locallanview
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
Remove-Item Env:GOOS, Env:GOARCH
Get-ChildItem dist | Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) } |
    Set-Content dist/SHA256SUMS
Get-Content dist/SHA256SUMS
