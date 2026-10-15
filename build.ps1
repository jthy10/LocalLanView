# Windows build script. Produces the same reproducible binaries as `make dist`.
#   .\build.ps1            build for this machine
#   .\build.ps1 -Dist      cross-compile every target into .\dist
param([switch]$Dist, [string]$Version)

$ErrorActionPreference = "Stop"
if (-not $Version) {
    $Version = (git describe --tags --always --dirty 2>$null)
    if (-not $Version) { $Version = "dev" }
}
if ($Version -notmatch '^[A-Za-z0-9._+-]+$') {
    Write-Error "Version must be letters, digits and ._+- only"
}
$ldflags = "-s -w -buildid= -X main.version=$Version"

# Put the caller's environment back afterwards, even if a build fails.
$saved = @{}
foreach ($name in "CGO_ENABLED", "GOOS", "GOARCH") {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$code = 0
try {
    $env:CGO_ENABLED = "0"
    if (-not $Dist) {
        go build -trimpath -buildvcs=false -ldflags $ldflags -o LocalLanView.exe ./cmd/locallanview
        $code = $LASTEXITCODE
    } else {
        Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
        New-Item -ItemType Directory dist | Out-Null
        $targets = "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"
        foreach ($t in $targets) {
            $os, $arch = $t.Split("/")
            $ext = if ($os -eq "windows") { ".exe" } else { "" }
            Write-Host "building $os/$arch"
            $env:GOOS = $os; $env:GOARCH = $arch
            go build -trimpath -buildvcs=false -ldflags $ldflags -o "dist/LocalLanView-$Version-$os-$arch$ext" ./cmd/locallanview
            if ($LASTEXITCODE -ne 0) { $code = $LASTEXITCODE; break }
        }
        if ($code -eq 0) {
            # Collect the hashes before writing, so SHA256SUMS doesn't list itself.
            $sums = Get-ChildItem dist -Filter "LocalLanView-*" | Get-FileHash -Algorithm SHA256 |
                ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) }
            $sums | Set-Content -Encoding ascii dist/SHA256SUMS
            Get-Content dist/SHA256SUMS
        }
    }
} finally {
    foreach ($name in $saved.Keys) {
        [Environment]::SetEnvironmentVariable($name, $saved[$name], "Process")
    }
}
exit $code
