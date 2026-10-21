# Build Sphinx.exe (one-file) and SphinxPortable.zip, with
# SHA256SUMS.txt — the fleet's release shape. Run from windows/:
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

# Checksums for both artifacts, verified by re-reading the files.
$lines = @()
foreach ($f in @('dist\Sphinx.exe', 'dist\SphinxPortable.zip')) {
    $hash = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    $lines += "$hash  $(Split-Path $f -Leaf)"
}
$lines | Set-Content 'dist\SHA256SUMS.txt' -Encoding ascii
Write-Host 'Built dist\Sphinx.exe, dist\SphinxPortable.zip, dist\SHA256SUMS.txt'
