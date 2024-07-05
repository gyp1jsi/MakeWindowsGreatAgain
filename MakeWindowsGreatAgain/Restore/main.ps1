$host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.0.0 - 2024.07.07 (Menu)"
# Define the folder where the scripts are located
$folderPath = "$PSScriptRoot\files"
# Define the files name
$services = "services.ps1"
$store = "store.ps1"
$teredo = "teredo.ps1"
$edge = "edge.ps1"

# Run the corresponding file to the pressed key
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
|                                        RESTORE TOOL                                         |
|---------------------------------------------------------------------------------------------|
| With this tool, you can restore some of your pre-script features and services.              |
|_____________________________________________________________________________________________|

1] Restore services
2] Install Microsoft Store
3] Enable Teredo
4] Install Microsoft Edge

Q -Quit
    
"@
    $key = [System.Console]::ReadKey($true)
    switch ($key.KeyChar) {
        1 { & "$folderPath\$services" }
        2 { & "$folderPath\$store" }
        3 { & "$folderPath\$teredo" }
        4 { & "$folderPath\$edge"}
        q { break }
        default { Write-Host "Invalid option." }
    }
} until ($key.KeyChar -eq "q")