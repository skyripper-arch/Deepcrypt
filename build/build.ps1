# Cross-compiles the Deepcrypt Go core for all target platforms.
# Run from any directory; paths are resolved relative to this script.
#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir   = Split-Path -Parent $ScriptDir
$GoDir     = Join-Path $RootDir 'go-core'
$OutDir    = Join-Path $RootDir 'binaries'

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Ldflags = '-s -w'

$Targets = @(
    @{ GOOS='linux';   GOARCH='amd64'; Name='dpc-linux-amd64'     },
    @{ GOOS='linux';   GOARCH='arm64'; Name='dpc-linux-arm64'     },
    @{ GOOS='linux';   GOARCH='arm';   GOARM='7'; Name='dpc-linux-arm' }, # Termux 32-bit
    @{ GOOS='darwin';  GOARCH='amd64'; Name='dpc-darwin-amd64'    },
    @{ GOOS='darwin';  GOARCH='arm64'; Name='dpc-darwin-arm64'    },
    @{ GOOS='windows'; GOARCH='amd64'; Name='dpc-win-amd64.exe'   },
    @{ GOOS='windows'; GOARCH='arm64'; Name='dpc-win-arm64.exe'   }
)

Write-Host '==> Building Deepcrypt (dpc) Go core'

Push-Location $GoDir
try {
    go mod download

    foreach ($t in $Targets) {
        $env:GOOS   = $t.GOOS
        $env:GOARCH = $t.GOARCH
        $env:GOARM  = if ($t.GOARM) { $t.GOARM } else { '' }
        $out = Join-Path $OutDir $t.Name
        Write-Host ("    {0,-10} {1,-6} -> {2}" -f $t.GOOS, $t.GOARCH, $t.Name)
        go build -ldflags $Ldflags -trimpath -o $out .
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $($t.Name)" }
    }
}
finally {
    $env:GOOS   = ''
    $env:GOARCH = ''
    $env:GOARM  = ''
    Pop-Location
}

Write-Host "==> Done. Binaries in $OutDir"
