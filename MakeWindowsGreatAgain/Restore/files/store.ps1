Write-Output "Downloading and installing Microsoft Store, it will take a while..."
# Define the URL of the ZIP file
$zipUrl = "https://github.com/kkkgo/LTSC-Add-MicrosoftStore/archive/refs/heads/master.zip"

# Define the path to download the ZIP file
$zipPath = "$env:TEMP\LTSC-Add-MicrosoftStore.zip"

# Define the extraction path
$extractPath = "$env:TEMP\LTSC-Add-MicrosoftStore"

# Download the ZIP file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

# Extract the ZIP file
Expand-Archive -Path $zipPath -DestinationPath $extractPath

# Run the Add-Store.cmd script as administrator
Start-Process -FilePath "$extractPath\LTSC-Add-MicrosoftStore-master\Add-Store.cmd" -Verb RunAs
