#Requires -Version 5.1
<#
.SYNOPSIS
    LumiNet - Full Build Script (Windows)

.DESCRIPTION
    Builds the complete LumiNet application:
      Step 1: Build Rust core library (cargo build --release)
      Step 2: Generate C header via cbindgen
      Step 3: Build web frontend (pnpm run build)
      Step 4: Build Go server binary with CGO

.EXAMPLE
    .\scripts\build-all.ps1
    .\scripts\build-all.ps1 -Configuration Debug
#>

[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [switch]$SkipWeb,
    [switch]$SkipTests,
    [switch]$Gui
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Constants ──────────────────────────────────────────────────────────────
$RootDir    = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CoreDir    = Join-Path $RootDir "core"
$ServerDir  = Join-Path $RootDir "server"
$WebDir     = Join-Path $RootDir "web"
$BuildDir   = Join-Path $RootDir "build"
$BinName    = "luminet.exe"
$HeaderFile = Join-Path $RootDir "luminet_core.h"

# -- Helpers ────────────────────────────────────────────────────────────────

function Write-StepHeader([string]$Tag, [string]$Message) {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor DarkGray
    Write-Host "  $Tag $Message" -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor DarkGray
}

function Write-Success([string]$Message) {
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-StepTime([System.Diagnostics.Stopwatch]$Timer) {
    $elapsed = $Timer.Elapsed
    Write-Host "  Elapsed: $($elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor DarkGray
}

function Assert-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "  [-] Required command not found: $Name" -ForegroundColor Red
        Write-Host "     Please install $Name and ensure it is on your PATH." -ForegroundColor Yellow
        exit 1
    }
}

function Invoke-Step([string]$Description, [scriptblock]$Action) {
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "Command exited with code $LASTEXITCODE"
        }
    }
    catch {
        Write-Host ""
        Write-Host "  [-] FAILED: $Description" -ForegroundColor Red
        Write-Host "     Error: $_" -ForegroundColor Red
        exit 1
    }
    finally {
        $timer.Stop()
        Write-StepTime $timer
    }
}

# -- Preamble ───────────────────────────────────────────────────────────────
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host ""
Write-Host "  LumiNet Build System" -ForegroundColor Magenta
Write-Host "     Configuration: $Configuration" -ForegroundColor DarkGray
Write-Host "     Platform:      Windows ($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor DarkGray
Write-Host ""

# -- Prerequisite Checks ───────────────────────────────────────────────────
Write-StepHeader "[*]" "Checking prerequisites..."
if (-not (Get-Command "gcc" -ErrorAction SilentlyContinue)) {
    $scoopMingw = Join-Path $env:USERPROFILE "scoop\apps\mingw\current\bin"
    if (Test-Path $scoopMingw) {
        $env:PATH = "$scoopMingw;$env:PATH"
    }
}
Assert-Command "cargo"
Assert-Command "cbindgen"
Assert-Command "go"
Assert-Command "gcc"
if (-not $SkipWeb) {
    Assert-Command "npm"
    Assert-Command "node"
}
Write-Success "All prerequisites found"

# -- Step 1: Build Rust Core ───────────────────────────────────────────────
Write-StepHeader "[1/4]" "Building Rust core library (GNU target)"
Invoke-Step "Rust build" {
    Push-Location $CoreDir
    try {
        $cargoArgs = @("build", "--target", "x86_64-pc-windows-gnu")
        if ($Configuration -eq "Release") {
            $cargoArgs += "--release"
        }
        if ($PSBoundParameters.ContainsKey('Verbose')) {
            $cargoArgs += "--verbose"
        }
        
        # Try offline build first to avoid network delays / SSL timeouts
        Write-Host "  [*] Attempting offline Rust build..." -ForegroundColor Gray
        & cargo @($cargoArgs + "--offline")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [*] Offline build failed/cache missing. Retrying online..." -ForegroundColor Yellow
            & cargo @cargoArgs
        }

        # Copy the resulting GNU library to the non-target directory where Go expects it
        $configSubdir = if ($Configuration -eq "Release") { "release" } else { "debug" }
        $srcLib = Join-Path $CoreDir "target\x86_64-pc-windows-gnu\$configSubdir\liblumicore.a"
        $destDir = Join-Path $CoreDir "target\$configSubdir"
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Copy-Item -Path $srcLib -Destination (Join-Path $destDir "liblumicore.a") -Force
    }
    finally {
        Pop-Location
    }
}
Write-Success "Rust core library built"

# -- Step 2: Generate C Header ─────────────────────────────────────────────
Write-StepHeader "[2/4]" "Generating C header (cbindgen)"
Invoke-Step "cbindgen" {
    Push-Location $CoreDir
    try {
        & cbindgen --config cbindgen.toml --crate lumicore --output $HeaderFile
    }
    finally {
        Pop-Location
    }
}
Write-Success "C header generated: $HeaderFile"

# -- Step 3: Build Web Frontend ────────────────────────────────────────────
if ($SkipWeb) {
    Write-StepHeader "[skip]" "Skipping web frontend (--SkipWeb)"
}
else {
    Write-StepHeader "[3/4]" "Building web frontend"
    Invoke-Step "Frontend install" {
        Push-Location $WebDir
        try {
            & npx pnpm install --frozen-lockfile
        }
        finally {
            Pop-Location
        }
    }
    Invoke-Step "Frontend build" {
        Push-Location $WebDir
        try {
            & npx pnpm run build
        }
        finally {
            Pop-Location
        }
    }
    Write-Success "Web frontend built"
}

# -- Step 4: Build Go Server ───────────────────────────────────────────────
Write-StepHeader "[4/4]" "Building Go server binary"

# Ensure build directory exists
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

Invoke-Step "Go build" {
    Push-Location $ServerDir
    try {
        $env:CGO_ENABLED = "1"

        # Compute version info
        $version = "v0.0.0-dev"
        try { $version = (git describe --tags --always --dirty 2>$null) } catch {}
        $commit = "unknown"
        try { $commit = (git rev-parse --short HEAD 2>$null) } catch {}
        $buildDate = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

        $ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.buildDate=$buildDate"
        if ($Gui) {
            $ldflags += " -H windowsgui"
        }
        $outPath = Join-Path $BuildDir $BinName

        & go build -trimpath -ldflags $ldflags -o $outPath .
    }
    finally {
        Pop-Location
    }
}
Write-Success "Go binary built: $BuildDir\$BinName"

# -- Summary ────────────────────────────────────────────────────────────────
$totalTimer.Stop()
$totalElapsed = $totalTimer.Elapsed

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  Binary:  $BuildDir\$BinName" -ForegroundColor White
Write-Host "  Config:  $Configuration" -ForegroundColor White
Write-Host "  Time:    $($totalElapsed.Minutes)m $($totalElapsed.Seconds)s" -ForegroundColor White
Write-Host ""
