<#
.SYNOPSIS
    Build and start LogGen, optionally with a local syslog sink.

.DESCRIPTION
    Stops any running instance, rebuilds with the version stamped in, starts the
    console, and prints the addresses it can be reached on.

    With -WithSink it also starts LogGen's built-in syslog receiver and points a
    destination at it, so records can be sent and seen without a SIEM.

.EXAMPLE
    .\scripts\start.ps1
    Build and run against the existing destinations.

.EXAMPLE
    .\scripts\start.ps1 -WithSink
    Build and run with a local sink, ready to send and verify immediately.

.EXAMPLE
    .\scripts\start.ps1 -Addr 127.0.0.1:8088
    Restrict the console to this machine.
#>
[CmdletBinding()]
param(
    # Address the console listens on. 0.0.0.0 makes it reachable from the network.
    [string]$Addr = '0.0.0.0:8088',

    # Also start a local syslog receiver and point a destination at it.
    [switch]$WithSink,

    # Port for that receiver. 514 needs elevation on most systems; 5514 does not.
    [int]$SinkPort = 5514,

    # Where profiles.json lives.
    [string]$Data = 'data',

    # Open a browser once the console is up.
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Say($msg) { Write-Host "  $msg" }

Write-Host ""
Write-Host "LogGen" -ForegroundColor Yellow

# --- stop anything already running -----------------------------------------
$running = Get-Process loggen -ErrorAction SilentlyContinue
if ($running) {
    Say "stopping $($running.Count) running instance(s)"
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 600
}

# --- build ------------------------------------------------------------------
$version = try { (git describe --tags --always --dirty 2>$null) } catch { 'dev' }
if (-not $version) { $version = 'dev' }

Say "building $version"
go build -ldflags "-s -w -X main.version=$version" -o loggen.exe .
if ($LASTEXITCODE -ne 0) { Write-Host "  build failed" -ForegroundColor Red; exit 1 }

# --- optional sink ----------------------------------------------------------
if ($WithSink) {
    Say "starting a syslog sink on :$SinkPort"
    Start-Process -FilePath "$root\loggen.exe" `
        -ArgumentList '-sink', ":$SinkPort" `
        -WorkingDirectory $root `
        -RedirectStandardOutput "$root\sink.log" `
        -RedirectStandardError "$root\sink.err" `
        -WindowStyle Hidden
    Start-Sleep -Milliseconds 400
}

# --- console ----------------------------------------------------------------
$consoleArgs = @('-addr', $Addr, '-data', $Data)
if (-not $Open) { $consoleArgs += '-open=false' }

Start-Process -FilePath "$root\loggen.exe" `
    -ArgumentList $consoleArgs `
    -WorkingDirectory $root `
    -RedirectStandardOutput "$root\loggen.log" `
    -RedirectStandardError "$root\loggen.err" `
    -WindowStyle Hidden

# Wait for it to answer rather than guessing at a sleep.
$port = ($Addr -split ':')[-1]
$ready = $false
foreach ($i in 1..30) {
    Start-Sleep -Milliseconds 400
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 `
            -Uri "http://127.0.0.1:$port/api/controls" | Out-Null
        $ready = $true
        break
    } catch { }
}

if (-not $ready) {
    Write-Host "  the console did not come up; last output:" -ForegroundColor Red
    Get-Content "$root\loggen.log", "$root\loggen.err" -ErrorAction SilentlyContinue |
        Select-Object -Last 15
    exit 1
}

# --- point a destination at the sink ---------------------------------------
if ($WithSink) {
    $body = @{
        name = "Local sink"; host = "127.0.0.1"; port = $SinkPort
        protocol = "udp"; isDefault = $true
    } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Method Post -TimeoutSec 5 `
            -Uri "http://127.0.0.1:$port/api/profiles" `
            -ContentType 'application/json' -Body $body | Out-Null
        Say "destination 'Local sink' points at 127.0.0.1:$SinkPort"
    } catch {
        Say "could not add the sink destination: $_"
    }
}

# --- report -----------------------------------------------------------------
$controls = (Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/controls" -TimeoutSec 5).Count
Say "$controls controls registered"
Write-Host ""

Get-Content "$root\loggen.log" -ErrorAction SilentlyContinue |
    Where-Object { $_ -match 'http://' } |
    ForEach-Object { Write-Host "  $($_ -replace '^\d\d:\d\d:\d\d\s+','')" -ForegroundColor Cyan }

Write-Host ""
if ($WithSink) {
    Say ("records land in sink.log - Get-Content sink.log -Wait")
}
Say ("stop with: Get-Process loggen | Stop-Process")
Write-Host ""
