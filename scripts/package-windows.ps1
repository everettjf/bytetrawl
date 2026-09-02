$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$OutputDir = if ($args.Count -gt 0) { $args[0] } else { Join-Path $ProjectRoot "dist" }
$Manifest = Get-Content (Join-Path $ProjectRoot "Cargo.toml") -Raw
$Version = [regex]::Match($Manifest, '(?m)^version = "([0-9.]+)"').Groups[1].Value
if (-not $Version) { throw "Could not read workspace version" }

Push-Location $ProjectRoot
try {
    cargo build --release --locked -p bytetrawl -p bytetrawl-cli
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $StageDir = Join-Path $OutputDir "ByteTrawl-$Version-windows-x64"
    if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
    New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
    Copy-Item target/release/ByteTrawl.exe, target/release/bytetrawl-cli.exe, LICENSE, README.md $StageDir

    $ZipPath = "$StageDir.zip"
    if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
    Compress-Archive -Path "$StageDir/*" -DestinationPath $ZipPath

    $Candle = Get-Command candle.exe -ErrorAction SilentlyContinue
    $Light = Get-Command light.exe -ErrorAction SilentlyContinue
    if (-not $Candle -or -not $Light) {
        $WixBin = Join-Path ${env:ProgramFiles(x86)} "WiX Toolset v3.14\bin"
        $Candle = Get-Item (Join-Path $WixBin "candle.exe") -ErrorAction SilentlyContinue
        $Light = Get-Item (Join-Path $WixBin "light.exe") -ErrorAction SilentlyContinue
    }
    if (-not $Candle -or -not $Light) {
        throw "WiX Toolset 3 (candle.exe and light.exe) is required"
    }

    $WixObject = Join-Path $OutputDir "bytetrawl.wixobj"
    & $Candle.Source -nologo -arch x64 "-dSourceDir=$StageDir" "-dProductVersion=$Version" `
        -out $WixObject packaging/windows/bytetrawl.wxs
    if ($LASTEXITCODE -ne 0) { throw "WiX candle failed" }

    $MsiPath = Join-Path $OutputDir "ByteTrawl-$Version-windows-x64.msi"
    & $Light.Source -nologo -sice:ICE61 -out $MsiPath $WixObject
    if ($LASTEXITCODE -ne 0) { throw "WiX light failed" }

    Write-Output $MsiPath
    Write-Output $ZipPath
} finally {
    Pop-Location
}
