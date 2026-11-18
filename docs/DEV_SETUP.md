# Developer setup (no admin rights required)

sandboxd builds natively on Linux, macOS and Windows. Every step below installs into your user
profile only.

## 1. Rust
- **Windows:** download `rustup-init.exe` from https://rustup.rs and run it. It installs to `%USERPROFILE%\.cargo`.
- **Linux / WSL / macOS:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`

`rust-toolchain.toml` pins the exact version, components and the `wasm32-wasip1` target. Cargo installs them automatically.

## 2. A C toolchain / linker

### Windows: portable MSVC (no installer, no admin)
Visual Studio Build Tools normally need admin rights. Use the portable extraction script instead.
It downloads the official Microsoft packages, verifies their SHA-256 hashes and unpacks them to a folder.

```powershell
mkdir D:\dev -Force; cd D:\dev      # any drive with ~1 GB free
Invoke-WebRequest https://gist.githubusercontent.com/mmozeiko/7f3162ec2988e81e56d5c4e22cde9977/raw/portable-msvc.py -OutFile portable-msvc.py
python portable-msvc.py --host x64 --target x64      # prompts you to accept the VS Build Tools license
```

Load the environment in each new shell before running `cargo` (or add it to your PowerShell profile):

```powershell
cmd /c "`"D:\dev\msvc\setup_x64.bat`" && set" | ForEach-Object {
  if ($_ -match '^(PATH|INCLUDE|LIB|VCToolsInstallDir|VCToolsVersion|WindowsSDKVersion|WindowsSdkBinPath)=(.*)$') {
    Set-Item "env:$($matches[1])" $matches[2]
  }
}
```

### WSL Ubuntu
Inside WSL, run once. This is root inside your Linux VM only, not on Windows:

```bash
sudo apt-get update && sudo apt-get install -y build-essential pkg-config
```

Clone or work under the Linux filesystem (`~/src/sandboxd`), not `/mnt/d/...`. Cross-filesystem builds are slow.

## 3. Guest interpreter assets
```bash
python scripts/fetch-assets.py          # downloads + verifies into assets/vendor/
```
For air-gapped builds, copy the files from `assets/manifest.toml` into a directory and set `SANDBOXD_ASSETS_DIR`.

## 4. Build & test
```bash
cargo build
cargo test --workspace
cargo run -p sandboxd -- version
```
