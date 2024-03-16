# MakeWindowsGreatAgain

This script aims to optimize Windows 10 and 11 by removing unuseful features and apps, as well as reducing idle RAM usage by disabling services you don't likely need to be running every time.

# PREREQUISITES:
1. Updating Windows FULLY (incl. optional updates)
2. Clean-Installed drivers (for NVIDIA use NVCleanInstall, for AMD use RadeonSoftwareSlimmer; disable and remove components as you prefer)

## You can download from the Releases page.
Extract the script and run "RUN ME AS ADMIN.bat", as administrator obviously.

### Extreme mode notes:
This mode disables core Windows functionalities. I will not give any active help. Though, I am leaving some information regarding services that handle specific functions.

Troubleshooting services: "Diagnostic Policy Service" (DPS) and "Diagnostic Execution Service" (diagsvc)

Printing services: Handled by "Server" (LanmanServer) and "Workstation" (LanmanWorkstation)

Trackpad: "ELAN Service" (ETDService)

NVIDIA Control Panel: "NVIDIA Display Container LS" (NVDisplay.ContainerLocalSystem)

# Contribute
If you want to contribute, feel free to create a Pull Request in "untested" branch. Your suggestion will be tested and committed to the main branch. 



