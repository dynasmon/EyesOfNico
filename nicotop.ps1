# Windows launcher. All arguments are forwarded to the compiled monitor.
$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'bin/nicotop.exe'
$needsBuild = -not (Test-Path $binary)
if (-not $needsBuild) {
    $builtAt = (Get-Item $binary).LastWriteTimeUtc
    $sources = @(Get-ChildItem (Join-Path $PSScriptRoot 'cmd'), (Join-Path $PSScriptRoot 'internal') -Recurse -Filter '*.go')
    $sources += Get-Item (Join-Path $PSScriptRoot 'go.mod'), (Join-Path $PSScriptRoot 'go.sum')
    $needsBuild = @($sources | Where-Object { $_.LastWriteTimeUtc -gt $builtAt }).Count -gt 0
}
if ($needsBuild) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'nicotop: install Go 1.24+ or use a prebuilt nicotop.exe.'
    }
    Write-Host 'Building EyesOfNico...'
    $previousCGO = $env:CGO_ENABLED
    Push-Location $PSScriptRoot
    try {
        $env:CGO_ENABLED = '0'
        & go build -trimpath '-ldflags=-s -w' -o $binary ./cmd/nicotop
        if ($LASTEXITCODE -ne 0) { throw 'nicotop: build failed.' }
    } finally {
        $env:CGO_ENABLED = $previousCGO
        Pop-Location
    }
}
& $binary @args
exit $LASTEXITCODE
