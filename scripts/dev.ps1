#Requires -Version 5.1
<#
.SYNOPSIS
    LumiNet - Development Mode (Windows)

.DESCRIPTION
    Starts the development environment with hot reload:
      1. Vite dev server for the React frontend
      2. Go server with air for hot reload
      3. Rust file watcher for automatic core rebuilds

    Press Ctrl+C to stop all processes.

.EXAMPLE
    .\scripts\dev.ps1
    .\scripts\dev.ps1 -Port 3000 -ApiPort 8990
#>

[CmdletBinding()]
param(
    [int]$Port = 5173,
    [int]$ApiPort = 8990,
    [switch]$SkipRustWatch,
    [switch]$SkipWeb
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Paths ──────────────────────────────────────────────────────────────────
$RootDir   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CoreDir   = Join-Path $RootDir "core"
$ServerDir = Join-Path $RootDir "server"
$WebDir    = Join-Path $RootDir "web"

# -- Helpers ────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  LumiNet Development Mode" -ForegroundColor Magenta
    Write-Host "  ---------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Frontend:  http://localhost:$Port" -ForegroundColor Cyan
    Write-Host "  API:       http://localhost:$ApiPort" -ForegroundColor Cyan
    Write-Host "  ---------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Press Ctrl+C to stop all processes" -ForegroundColor Yellow
    Write-Host ""
}

function Assert-Command([string]$Name, [string]$InstallHint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "  [-] Required: $Name" -ForegroundColor Red
        if ($InstallHint) {
            Write-Host "     Install: $InstallHint" -ForegroundColor Yellow
        }
        exit 1
    }
}

# -- Prerequisite Checks ───────────────────────────────────────────────────
Assert-Command "go" "https://go.dev/dl/"
Assert-Command "air" "go install github.com/air-verse/air@latest"
if (-not $SkipWeb) {
    Assert-Command "npm" "npm install -g pnpm"
    Assert-Command "node" "https://nodejs.org/"
}
if (-not $SkipRustWatch) {
    Assert-Command "cargo" "https://rustup.rs/"
    Assert-Command "cargo-watch" "cargo install cargo-watch"
}

# -- Process Tracking ──────────────────────────────────────────────────────
$jobs = @()

function Cleanup {
    Write-Host ""
    Write-Host "  [-] Shutting down dev processes..." -ForegroundColor Yellow
    foreach ($job in $jobs) {
        if ($job -and -not $job.HasExited) {
            try {
                Stop-Process -Id $job.Id -Force -ErrorAction SilentlyContinue
                Write-Host "     Stopped PID $($job.Id)" -ForegroundColor DarkGray
            }
            catch {}
        }
    }
    # Also stop any background jobs
    Get-Job | Where-Object { $_.State -eq "Running" } | Stop-Job
    Get-Job | Remove-Job -Force
    Write-Host "  [+] All processes stopped" -ForegroundColor Green
}

# Register cleanup on script exit
$null = Register-EngineEvent PowerShell.Exiting -Action { Cleanup }
trap { Cleanup; break }

# -- Initial Rust Build ────────────────────────────────────────────────────
Write-Host "  [*] Building Rust core (initial)..." -ForegroundColor Cyan
Push-Location $CoreDir
try {
    & cargo build
    if ($LASTEXITCODE -ne 0) { throw "Initial Rust build failed" }
    & cbindgen --config cbindgen.toml --crate lumicore --output (Join-Path $RootDir "luminet_core.h")
}
finally {
    Pop-Location
}
Write-Host "  [+] Rust core ready" -ForegroundColor Green

# -- Start Vite Dev Server ─────────────────────────────────────────────────
if (-not $SkipWeb) {
    Write-Host "  [*] Starting Vite dev server on :$Port..." -ForegroundColor Cyan
    $viteJob = Start-Process -NoNewWindow -PassThru -FilePath "npx" `
        -ArgumentList "pnpm", "run", "dev", "--", "--port", $Port `
        -WorkingDirectory $WebDir
    $jobs += $viteJob
}

# -- Start Go Server with Air ──────────────────────────────────────────────
Write-Host "  [*] Starting Go server with air on :$ApiPort..." -ForegroundColor Cyan
$env:LUMINET_PORT = $ApiPort
$env:LUMINET_DEV = "true"
$env:CGO_ENABLED = "1"

$airJob = Start-Process -NoNewWindow -PassThru -FilePath "air" `
    -ArgumentList "-c", ".air.toml" `
    -WorkingDirectory $ServerDir
$jobs += $airJob

# -- Start Rust File Watcher ───────────────────────────────────────────────
if (-not $SkipRustWatch) {
    Write-Host "  [*] Starting Rust file watcher..." -ForegroundColor Cyan
    $rustWatchJob = Start-Process -NoNewWindow -PassThru -FilePath "cargo" `
        -ArgumentList "watch", "-w", "src", "-s", "cargo build && cbindgen --config cbindgen.toml --crate lumicore --output ../luminet_core.h" `
        -WorkingDirectory $CoreDir
    $jobs += $rustWatchJob
}

# -- Banner & Wait ─────────────────────────────────────────────────────────
Write-Banner

try {
    # Wait for any process to exit (which likely means an error)
    while ($true) {
        Start-Sleep -Seconds 2
        foreach ($job in $jobs) {
            if ($job.HasExited) {
                Write-Host "  [-] Process $($job.Id) exited with code $($job.ExitCode)" -ForegroundColor Yellow
                Cleanup
                exit $job.ExitCode
            }
        }
    }
}
finally {
    Cleanup
}
