$host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.0.0 - 2024.07.07 (Menu)"

Write-Output "DID YOU INSTALL EVERY UPDATE? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output "DID YOU INSTALL ALL NEWEST DRIVERS? (y/n)"
    $confirm = Read-Host
    if ($confirm -eq "y") {
        Write-Output "DID YOU INSTALL BASIC PROGRAMS (e.g. Google Chrome)? (y/n)"
        $confirm = Read-Host
        if ($confirm -eq "y") {
            $scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
            $folderPath = Join-Path $scriptPath "files"
            $hardFile = "hard.ps1"
            $softFile = "soft.ps1"
            $extremeFile = "extreme.ps1"

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
| To "Alessio il fai da te": Why do you keep defending yourself against evidence? Before      |
| saying anything about me, LOOK AT YOURSELF. Yes, we do not know each other, still you keep  |
| threatening of doxxing other people that, still, you do not know. Why do I call you badly?  |
| Because that's who you are. You are just A RETARDED DOXXER.                                 |
|                                                                                             |
| To "zBloodwyn": YOUR BOOTLEG SCUMMY CTT SCRIPT BULLSHIT IS ABOUT TO END SOON!               | 
| You are still in time to end your circus and get an honest job, instead of scamming people. |
| But be quick, I AM COMING.                                                                  |
|                                                                                             |
| To ModiciaOS team: Are you so butthurt that you DMCA claim every critique towards your lame |
| distro? You must be more experienced than me, yet you seem clearly retarded and unable to   |
| take critiques as improvement. By the way, your distro SUCKS ASS. Report me, I dare you.    |
| #freecikappa                                                                                |
|                                                                                             |
| To Aurora: You should stop faking your entire personality on Telegram, we all know you are  |
| NOT who you tell us. And, before calling our age checks illegal, maybe think twice before   |
| selling other people's pictures on OnlyFans. I highly recommend you to touch grass, MORON.  |
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
        } else {
            Write-Output "Run again the script when you'll have done everything."
            timeout /t 7
        }
    } else {
        Write-Output "Run again the script when you'll have done everything."
        timeout /t 7
    }
} else {
    Write-Output "Run again the script when you'll have done everything."
    timeout /t 7
}
