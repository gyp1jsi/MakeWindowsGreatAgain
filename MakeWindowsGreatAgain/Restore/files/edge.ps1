# PowerShell script to download and install Microsoft Edge

# Define the URL for the Microsoft Edge installer
$installerUrl = "https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en&brand=M100"

# Define the path to save the installer
$installerPath = "$env:TEMP\MicrosoftEdgeSetup.exe"

# Download the installer
Write-Host "Downloading Microsoft Edge installer..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

# Check if the download was successful
if (Test-Path $installerPath) {
    Write-Host "Download completed. Installing Microsoft Edge..."
    
    # Start the installation process
    Start-Process -FilePath $installerPath -ArgumentList "/install"
    
    # Check if Edge was installed successfully
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if (Test-Path $edgePath) {
        Write-Host "Microsoft Edge installed successfully."
    } else {
        Write-Host "Microsoft Edge installation failed."
    }
    
    # Clean up the installer
    Remove-Item $installerPath
} else {
    Write-Host "Failed to download the installer."
}
