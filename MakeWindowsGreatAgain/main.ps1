# Ottenere il percorso assoluto della directory in cui si trova lo script
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# Definire il percorso della cartella che contiene i file, utilizzando il percorso assoluto della directory in cui si trova lo script
$folderPath = Join-Path $scriptPath "files"

# Definire i nomi dei file da avviare
$hardFile = "hard.ps1"
$softFile = "soft.ps1"
$midinstallFile = "midinstall.ps1"

# Avviare il file corrispondente al tasto premuto
do {
    Write-Host "1. Hard Mode - General script for users that want the maximum level of debloat. You can decide whether to run each part of the script."
    Write-Host "2. Soft Mode - Script for who wants a lighter debloat, keeping more apps and services. Recommended on your mom's computer. You can decide whether to run each part of the script."
    Write-Host "3. Mid-Install Mode - Script for those who updated Windows, and it re-enabled services that had been disabled before. You can decide whether to run each part of the script."
    Write-Host "Press 1 for Hard Mode, 2 for Soft Mode or 3 for Mid-Install mode (after updates). Press Q to exit."
    $key = [System.Console]::ReadKey($true)
    switch ($key.KeyChar) {
        1 { & "$folderPath\$hardFile" }
        2 { & "$folderPath\$softFile" }
        3 { & "$folderPath\$midinstallFile" }
        q { break }
        default { Write-Host "Opzione non valida." }
    }
} until ($key.KeyChar -eq "q")