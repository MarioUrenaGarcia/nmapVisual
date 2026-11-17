# Arranca nmap Visual. No requiere dependencias externas: solo Python 3.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

function Find-Python {
    foreach ($name in @("python", "py")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            try {
                $v = & $name --version 2>&1
                if ($v -match "Python 3") { return $name }
            } catch { }
        }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Host "No se encontro Python 3. Instalalo desde python.org y vuelve a intentarlo." -ForegroundColor Red
    exit 1
}

Write-Host "Iniciando nmap Visual..." -ForegroundColor Green
& $python (Join-Path $root "backend\app.py")
