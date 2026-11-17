# Crea un acceso directo "nmap Visual" en el Escritorio que abre la app sin consola.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Find-Pythonw {
    $cmd = Get-Command pythonw -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        $candidate = Join-Path (Split-Path $py.Source) "pythonw.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

$pythonw = Find-Pythonw
if (-not $pythonw) {
    Write-Host "No se encontro pythonw.exe. Instala Python 3 desde python.org." -ForegroundColor Red
    exit 1
}

# Icono: usa el del propio nmap si esta disponible.
$icon = $pythonw
foreach ($p in @("C:\Program Files (x86)\Nmap\nmap.exe", "C:\Program Files\Nmap\nmap.exe")) {
    if (Test-Path $p) { $icon = $p; break }
}

$desktop = [Environment]::GetFolderPath("Desktop")
$linkPath = Join-Path $desktop "nmap Visual.lnk"

$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($linkPath)
$sc.TargetPath = $pythonw
$sc.Arguments = '"' + (Join-Path $root "backend\app.py") + '"'
$sc.WorkingDirectory = $root
$sc.IconLocation = "$icon,0"
$sc.Description = "Interfaz visual para nmap"
$sc.WindowStyle = 7
$sc.Save()

Write-Host "Acceso directo creado en el Escritorio: $linkPath" -ForegroundColor Green
