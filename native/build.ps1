# Build spacecop_crypto.dll on Windows with MinGW-w64 gcc (present on GitHub
# runners and in MSYS2).  Output: spacecop\crypto\lib\spacecop_crypto.dll
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "..\spacecop\crypto\lib"
New-Item -ItemType Directory -Force $out | Out-Null
$target = Join-Path $out "spacecop_crypto.dll"
gcc -O3 -std=c99 -Wall -Wextra -shared -o $target (Join-Path $here "spacecop_crypto.c")
Write-Host "built $target"
