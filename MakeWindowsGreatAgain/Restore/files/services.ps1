# AUTOMATIC
# Define the file path for the input list of service names
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