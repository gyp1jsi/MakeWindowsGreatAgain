Write-Output "DID YOU INSTALL EVERY UPDATE? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output "DID YOU INSTALL ALL NEWEST DRIVERS? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output "DID YOU INSTALL BASIC PROGRAMS (e.g. Google Chrome)? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    # Ottenere il percorso assoluto della directory in cui si trova lo script
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# Definire il percorso della cartella che contiene i file, utilizzando il percorso assoluto della directory in cui si trova lo script
$folderPath = Join-Path $scriptPath "files"

# Definire i nomi dei file da avviare
$hardFile = "hard.ps1"
$softFile = "soft.ps1"

# Avviare il file corrispondente al tasto premuto
do {
    Write-Host ""
    Write-Host "        'ALESSIO IL FAI DA TE' IS A RETARDED DOXXER, 'ZBLOODWYN' SELLS A MODIFIED VERSION OF CTT WINUTIL"
    Write-Host "       _____________.___.__________.___     ____. _________.___    ____________________________.________________________"
    Write-Host "      /  _____/\__  |   |\______   \   |   |    |/   _____/|   |  /   _____/\_   ___ \______   \   \______   \__    ___/"
    Write-Host "     /   \  ___ /   |   | |     ___/   |   |    |\_____  \ |   |  \_____  \ /    \  \/|       _/   ||     ___/ |    |   "
    Write-Host "     \    \_\  \\____   | |    |   |   /\__|    |/        \|   |  /        \\     \___|    |   \   ||    |     |    |   "
    Write-Host "      \______  // ______| |____|   |___\________/_______  /|___| /_______  / \______  /____|_  /___||____|     |____|   "
    Write-Host "             \/ \/                                      \/               \/         \/       \/                         "
    Write-Host ""
    Write-Host ""
    Write-Host "      ______ _   _ _____  _   __  ______  ___  ___________    _____ _____ ______ ___________ _____ _____ "
    Write-Host "      |  ___| | | /  __ \| | / /  | ___ \/ _ \|_   _|  _  \  /  ___/  __ \| ___ \_   _| ___ \_   _/  ___|"
    Write-Host "      | |_  | | | | /  \/| |/ /   | |_/ / /_\ \ | | | | | |  \ `--.| /  \/| |_/ / | | | |_/ / | | \ `--. "
    Write-Host "      |  _| | | | | |    |    \   |  __/|  _  | | | | | | |   `--. \ |    |    /  | | |  __/  | |  `--. \"
    Write-Host "      | |   | |_| | \__/\| |\  \  | |   | | | |_| |_| |/ /   /\__/ / \__/\| |\ \ _| |_| |     | | /\__/ /"
    Write-Host "      \_|    \___/ \____/\_| \_/  \_|   \_| |_/\___/|___/    \____/ \____/\_| \_|\___/\_|     \_/ \____/ "
    Write-Host ""
    Write-Host ""
    Write-Host "1. Hard Mode - Full Power."
    Write-Host ""
    Write-Host "2. Soft Mode - Mom's computer."
    Write-Host ""
    Write-Host ""
    Write-Host "Press 1 for Hard Mode or 2 for Soft Mode. Press Q to exit."
    $key = [System.Console]::ReadKey($true)
    switch ($key.KeyChar) {
        1 { & "$folderPath\$hardFile" }
        2 { & "$folderPath\$softFile" }
        q { break }
        default { Write-Host "Invalid option." }
    }
} until ($key.KeyChar -eq "q")
    
}
else {
    Write-Output "Run again the script when you'll have done everything."
}
    
}
else {
    Write-Output "Run again the script when you'll have done everything."
}
}
else {
    Write-Output "Run again the script when you'll have done everything."
}






