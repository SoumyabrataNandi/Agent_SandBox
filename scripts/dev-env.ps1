# Load the no-admin Windows dev environment into the current PowerShell session.
#   . .\scripts\dev-env.ps1
# Defaults match docs/DEV_SETUP.md; override with $env:SANDBOXD_MSVC_DIR before dot-sourcing.

$msvc = if ($env:SANDBOXD_MSVC_DIR) { $env:SANDBOXD_MSVC_DIR } else { 'D:\dev\msvc' }
if (-not $env:RUSTUP_HOME) { $env:RUSTUP_HOME = 'D:\dev\rustup' }
if (-not $env:CARGO_HOME)  { $env:CARGO_HOME  = 'D:\dev\cargo' }
if ($env:Path -notlike "*$($env:CARGO_HOME)\bin*") { $env:Path = "$($env:CARGO_HOME)\bin;$env:Path" }

$setup = Join-Path $msvc 'setup_x64.bat'
if (-not (Test-Path $setup)) { throw "MSVC setup script not found at $setup (see docs/DEV_SETUP.md)" }

cmd /c "`"$setup`" && set" | ForEach-Object {
    if ($_ -match '^(PATH|INCLUDE|LIB|VCToolsInstallDir|VCToolsVersion|WindowsSDKVersion|WindowsSdkBinPath|VSCMD_ARG_HOST_ARCH|VSCMD_ARG_TGT_ARCH)=(.*)$') {
        Set-Item "env:$($matches[1])" $matches[2]
    }
}
Write-Host "sandboxd dev env loaded: $(cargo --version) | link: $((Get-Command link.exe).Source)"
