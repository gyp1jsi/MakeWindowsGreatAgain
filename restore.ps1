$host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Restore Tool)"

# Menu
function Show-Menu {
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Menu)"
    Clear-Host
    Write-Output "          __  __       _      __        ___           _                    "
    Write-Output "         |  \/  | __ _| | ____\ \      / (_)_ __   __| | _____      _____  "
    Write-Output "         | |\/| |/ _` | |/ / _ \ \ /\ / /| | '_ \ / _` |/ _ \ \ /\ / / __| "
    Write-Output "         | |  | | (_| |   <  __/\ V  V / | | | | | (_| | (_) \ V  V /\__ \ "
    Write-Output "         |_|__|_|\__,_|_|\_\___| \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/ "
    Write-Output "             / ___|_ __ ___  __ _| |_   / \   __ _  __ _(_)_ __            "
    Write-Output "            | |  _| '__/ _ \/ _` | __| / _ \ / _` |/ _` | | '_ \           "
    Write-Output "            | |_| | | |  __/ (_| | |_ / ___ \ (_| | (_| | | | | |          "
    Write-Output "             \____|_|  \___|\__,_|\__/_/   \_\__, |\__,_|_|_| |_|          "
    Write-Output "                                              |___/                        "
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "        [1] - Install MS Edge                       [2] - Restore Services"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "        [Q] - Quit"
    Write-Output ""
    Write-Output ""

    $key = Read-Host "Select an option and press Enter: "
    switch ($key) {
        1 {Install-Edge}
        2 {Restore-Services}
        q {break}
    }
}

# Install Edge
function Install-Edge {
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Install Edge)"
    Clear-Host
    Write-Output "Checking for existing WinGet installation..."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Install-Script winget-install -Force
        Write-Output "WinGet installed."
    } else {
        Write-Output "WinGet is already installed."
    }
    Write-Output "Installing Microsoft Edge..."
    winget install --id Microsoft.Edge -e --source winget
    Write-Output "Microsoft Edge installed."
    timeout /t 3
    Show-Menu
}

# Restore Services
function Restore-Services {
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Restore Services)"
    Clear-Host
    Write-Output "Restoring essential Windows services..."
$inputFilePath = "C:\MakeWindowsGreatAgain\backup\autoserv.txt"

# Get service names from the input file
$serviceNames = Get-Content -Path $inputFilePath

# Loop through each service name and set its start type to Manual
foreach ($serviceName in $serviceNames) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -ne $null) {
        Set-Service -Name $serviceName -StartupType Automatic
        Write-Output "Set service '$serviceName' to Automatic start type."
    } else {
        Write-Output "Service '$serviceName' not found."
    }
}

# MANUAL
# Define the file path for the input list of service names
$inputFilePath = "C:\MakeWindowsGreatAgain\backup\manserv.txt"

# Get service names from the input file
$serviceNames = Get-Content -Path $inputFilePath

# Loop through each service name and set its start type to Manual
foreach ($serviceName in $serviceNames) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -ne $null) {
        Set-Service -Name $serviceName -StartupType Manual
        Write-Output "Set service '$serviceName' to Manual start type."
    } else {
        Write-Output "Service '$serviceName' not found."
    }
}

# DISABLED
# Define the file path for the input list of service names
$inputFilePath = "C:\MakeWindowsGreatAgain\backup\disserv.txt"

# Get service names from the input file
$serviceNames = Get-Content -Path $inputFilePath

# Loop through each service name and set its start type to Manual
foreach ($serviceName in $serviceNames) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -ne $null) {
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Output "Set service '$serviceName' to Disabled start type."
    } else {
        Write-Output "Service '$serviceName' not found."
    }
}
    Write-Output "Essential Windows services restored."
    timeout /t 3
    Show-Menu
}