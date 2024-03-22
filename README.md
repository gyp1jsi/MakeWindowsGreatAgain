# **MakeWindowsGreatAgain**

This script aims to **optimize** Windows 10 and 11 by removing unuseful features and apps, as well as **reducing** idle RAM usage by **disabling** services you don't likely need to be running every time.

# PREREQUISITES:
1. Updating Windows FULLY (incl. optional updates)
2. Clean-Installed drivers (for NVIDIA use [NVCleanInstall](https://www.techpowerup.com/download/techpowerup-nvcleanstall/), for AMD use [RadeonSoftwareSlimmer](https://github.com/GSDragoon/RadeonSoftwareSlimmer); disable and remove components as you prefer)

## You can download from the [Releases](https://github.com/gyp1jsi/MakeWindowsGreatAgain/releases) page.
Extract the script and run "RUN ME AS ADMIN.bat", as administrator obviously.

### Extreme mode notes:
This mode disables core Windows functionalities. I will not give any active help. Though, I am leaving some information regarding services that handle specific functions.

Troubleshooting services: "_Diagnostic Policy Service_" (DPS) and "_Diagnostic Execution Service_" (diagsvc)

Printing services: "_Print Spooler_" (Spooler), "_PrintNotify_" (Printer Extensions and Notifications) "_Server_" (LanmanServer) and "_Workstation_" (LanmanWorkstation); these 4 need to be set as "Automatic" to work. Manual mode will **NOT** trigger them to run when needed!

Some ELAN/I2C Trackpads: "_ELAN Service_" (ETDService)

NVIDIA Control Panel: "_NVIDIA Display Container LS_" (NVDisplay.ContainerLocalSystem)

# Contribute
If you want to contribute, feel free to create a Pull Request in "untested" branch. Your suggestion will be tested and committed to the main branch. 