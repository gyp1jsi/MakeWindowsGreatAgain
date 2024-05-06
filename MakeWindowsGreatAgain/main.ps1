$host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.0.0 - 2024.06.07 (Menu)"

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
$extremeFile = "extreme.ps1"

# Avviare il file corrispondente al tasto premuto
do {
    Write-Host @"
                                                                                        
    _____     _____      _____      _____    ____         ____          ______   ____ 
    ___|\    \   |\    \    /    /| ___|\    \  |    |       |    |     ___|\     \ |    |
    /    /\    \  | \    \  /    / ||    |\    \ |    |       |    |    |    |\     \|    |
    |    |  |____| |  \____\/    /  /|    | |    ||    |       |    |    |    |/____/||    |
    |    |    ____  \ |    /    /  / |    |/____/||    | ____  |    | ___|    \|   | ||    |
    |    |   |    |  \|___/    /  /  |    ||    |||    ||    | |    ||    \    \___|/ |    |
    |    |   |_,  |      /    /  /   |    ||____|/|    ||    | |    ||    |\     \    |    |
    |\ ___\___/  /|     /____/  /    |____|       |____||\____\|____||\ ___\|_____|   |____|
    | |   /____ / |    |`    | /     |    |       |    || |    |    || |    |     |   |    |
    \|___|    | /     |_____|/      |____|       |____| \|____|____| \|____|_____|   |____|
     \( |____|/         )/           \(           \(      \(   )/      \(    )/       \(  
      '   )/            '             '            '       '   '        '    '         '                                                                                 
 _____________________________________________________________________________________________
|                                                                                             |
|                                           PRESENTS                                          |
|                               /-----------------------------\                               |
|                               | MakeWindowsGreatAgain 2.0.0 |                               |
|                               \-----------------------------/                               |           
|                                                                                             |
|---------------------------------------------------------------------------------------------|
| Personal notes:                                                                             |
|                                                                                             |
| To "Alessio il fai da te": Why do you keep defending yourself against evidence? What would  |
| you do if you were standing right in front of me? NOTHING. So, before saying anything about |
| me, LOOK AT YOURSELF. Yes, we do not know each other, still you keep threatening of doxxing |
| other people that, still, you do not know.                                                  |
| Why do I call you badly? Because that's who you are. In the eyes of any user, you are just  |
| A RETARDED DOXXER.                                                                          |
|                                                                                             |
| To "zBloodwyn": YOUR BOOTLEG SCUMMY CTT SCRIPT BULLSHIT IS ABOUT TO END SOON!               | 
| You are still in time to end your circus and get an honest job, instead of scamming people. |
| But be quick, I AM COMING.                                                                  |
|                                                                                             |
| To ModiciaOS team: Are you so butthurt that you DMCA claim every critique towards your lame |
| distro? You must be more experienced than me, yet you seem clearly retarded and unable to   |
| take critiques as improvement. By the way, your distro SUCKS ASS. Report me, I dare you.    |
| #freecikappa                                                                                |
|_____________________________________________________________________________________________|

1] Hard Mode (Recommended)
2] Soft Mode (Mom's computer)
3] Extreme Mode (Experts only, self-troubleshooting)

Q -Quit
    
"@
    $key = [System.Console]::ReadKey($true)
    switch ($key.KeyChar) {
        1 { & "$folderPath\$hardFile" }
        2 { & "$folderPath\$softFile" }
        3 { & "$folderPath\$extremeFile" }
        q { break }
        default { Write-Host "Invalid option." }
    }
} until ($key.KeyChar -eq "q")
    
}
else {
    Write-Output "Run again the script when you'll have done everything."
    timeout /t 7
}
    
}
else {
    Write-Output "Run again the script when you'll have done everything."
    timeout /t 7
}
}
else {
    Write-Output "Run again the script when you'll have done everything."
    timeout /t 7
}