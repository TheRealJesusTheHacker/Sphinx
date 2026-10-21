# Build Sphinx.exe (one-file), SphinxPortable.zip, and — when Inno
# Setup is installed — SphinxSetup.exe, with SHA256SUMS.txt over all
# of them: the fleet's release shape. Run from windows/:
#   powershell -ExecutionPolicy Bypass -File packaging/build-portable.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

python -m pip install -r requirements-dev.txt
python -m pytest tests -q
python -m PyInstaller packaging/Sphinx.spec --noconfirm --distpath dist --workpath build/pyi

# Portable edition: the exe plus the portable.txt marker. With the
# marker beside it, the app keeps its data in .\data next to the exe
# instead of %LOCALAPPDATA% — the whole folder can be carried and run.
$portable = Join-Path (Get-Location) 'dist\SphinxPortable'
New-Item -ItemType Directory -Force $portable | Out-Null
Copy-Item 'dist\Sphinx.exe' $portable
New-Item -ItemType File -Force (Join-Path $portable 'portable.txt') | Out-Null
Compress-Archive -Path $portable -DestinationPath 'dist\SphinxPortable.zip' -Force

# Installer edition (Inno Setup). Optional locally — CI always
# builds it — so a dev machine without Inno still produces the
# portable shape unchanged.
$built = @('dist\Sphinx.exe', 'dist\SphinxPortable.zip')
$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if ($iscc) {
    & $iscc.Source 'packaging\Sphinx.iss'
    $built += 'dist\SphinxSetup.exe'
} else {
    Write-Host 'Inno Setup (iscc) not found — skipping SphinxSetup.exe'
}

# Checksums for every artifact built, verified by re-reading the files.
$lines = @()
foreach ($f in $built) {
    $hash = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    $lines += "$hash  $(Split-Path $f -Leaf)"
}
$lines | Set-Content 'dist\SHA256SUMS.txt' -Encoding ascii
Write-Host "Built $($built -join ', '), dist\SHA256SUMS.txt"
