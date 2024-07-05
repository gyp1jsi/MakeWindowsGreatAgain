# For those who don't rape Windows
$host.ui.RawUI.WindowTitle = 'MakeWindowsGreatAgain 2.0.0 - 2024.07.07 (Soft)'
timeout /t 2
# Pre-Installed Bloatware
Write-Output "Do you want to uninstall preinstalled bloatware apps? (y/n)"
$confirm = Read-Host

if ($confirm -eq "y") {
    Write-Output "Fetching AppX installed apps and removing them, please wait..."
    $AppXApps = @(
    
    # Default Windows 10+ apps
            "Microsoft.3DBuilder"                    # 3D Builder
            "Microsoft.549981C3F5F10"                # Cortana
            "Microsoft.Appconnector"
            "Microsoft.BingFinance"                  # Finance
            "Microsoft.BingFoodAndDrink"             # Food And Drink
            "Microsoft.BingHealthAndFitness"         # Health And Fitness
            "Microsoft.BingNews"                     # News
            "Microsoft.BingSports"                   # Sports
            "Microsoft.BingTranslator"               # Translator
            "Microsoft.BingTravel"                   # Travel
            "Microsoft.CommsPhone"
            "Microsoft.ConnectivityStore"
            "Microsoft.GetHelp"
            "Microsoft.Getstarted"
            "Microsoft.Messaging"
            "Microsoft.Microsoft3DViewer"
            "Microsoft.MicrosoftPowerBIForWindows"
            "Microsoft.MicrosoftSolitaireCollection" # MS Solitaire
            "Microsoft.MixedReality.Portal"
            "Microsoft.NetworkSpeedTest"
            "Microsoft.OneConnect"
            "Microsoft.People"                       # People
            "Microsoft.MSPaint"                      # Paint 3D
            "Microsoft.Print3D"                      # Print 3D
            "Microsoft.SkypeApp"                     # Skype (Who still uses Skype? Use Discord)
            "Microsoft.Todos"                        # Microsoft To Do
            "Microsoft.Wallet"
            "microsoft.windowscommunicationsapps"
            "Microsoft.WindowsMaps"                  # Maps
            "Microsoft.WindowsReadingList"
            "MicrosoftCorporationII.MicrosoftFamily" # Parental Control (no kids allowed here)
    
            # Default Windows 11 apps
            "Clipchamp.Clipchamp"		     	     # Clipchamp (Shitty Video Editor)
            "MicrosoftWindows.Client.WebExperience"  # Taskbar Widgets
            "MicrosoftTeams"                         # Microsoft Teams / Preview
            "*Teams*"                                # Chat
    
            # 3rd party Apps
            "*ACGMediaPlayer*"
            "*ActiproSoftwareLLC*"
            "*AdobePhotoshopExpress*"                # Adobe Photoshop Express
            "*Amazon.com.Amazon*"                    # Amazon Shop
            "*Asphalt8Airborne*"                     # Asphalt 8 Airbone
            "*AutodeskSketchBook*"
            "*BubbleWitch3Saga*"                     # Bubble Witch 3 Saga
            "*CaesarsSlotsFreeCasino*"
            "*CandyCrush*"                           # Candy Crush
            "*COOKINGFEVER*"
            "*CyberLinkMediaSuiteEssentials*"
            "*DisneyMagicKingdoms*"
            "*DrawboardPDF*"
            "*Duolingo-LearnLanguagesforFree*"       # Duolingo
            "*EclipseManager*"
            "*Facebook*"                             # Facebook
            "*FarmVille2CountryEscape*"
            "*FitbitCoach*"
            "*Flipboard*"                            # Flipboard
            "*HiddenCity*"
            "*Hulu*"
            "*iHeartRadio*"
            "*Keeper*"
            "*LinkedInforWindows*"
            "*MarchofEmpires*"
            "*NYTCrossword*"
            "*OneCalendar*"
            "*PandoraMediaInc*"
            "*PhototasticCollage*"
            "*PicsArt-PhotoStudio*"
            "*Plex*"                                 # Plex
            "*PolarrPhotoEditorAcademicEdition*"
            "*RoyalRevolt*"                          # Royal Revolt
            "*Shazam*"
            "*Sidia.LiveWallpaper*"                  # Live Wallpaper
            "*SlingTV*"
            "*Speed Test*"
            "*Sway*"
            "*TuneInRadio*"
            "*Twitter*"                              # Twitter
            "*Viber*"
            "*WinZipUniversal*"
            "*Wunderlist*"
            "*XING*"
            "*Messenger*"
            "*Instagram*"
            "*Facebook.InstagramBeta*"
            "*BytedancePte.Ltd.TikTok*"
            "*PrimeVideo*"
            "*AmazonVideo.PrimeVideo*"              #If the above does not work
            "*Disney*"
            "*Disney.37853FC22B2CE*"                #If the above does not work
    
    
            # SAMSUNG Bloat
            #"SAMSUNGELECTRONICSCO.LTD.SamsungSettings1.2"          # Allow user to Tweak some hardware settings
            "SAMSUNGELECTRONICSCO.LTD.1412377A9806A"
            "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote"
            "SAMSUNGELECTRONICSCoLtd.SamsungNotes"
            "SAMSUNGELECTRONICSCoLtd.SamsungFlux"
            "SAMSUNGELECTRONICSCO.LTD.StudioPlus"
            "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome"
            "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate"
            "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2"
            "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording"
            #"SAMSUNGELECTRONICSCO.LTD.SamsungRecovery"             # Used to Factory Reset
            "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch"
            "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
            "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync"
            "SAMSUNGELECTRONICSCO.LTD.PCGallery"
            "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
            "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION"
    
            "Microsoft.MicrosoftStickyNotes"    # Sticky Notes
            "Microsoft.WindowsFeedbackHub"      # Feedback Hub
    
            # [DIY] Common Streaming services
    
            "*Netflix*"                        # Netflix
            "*Spotify*"                        # Spotify
        )
        foreach ($App in $AppXApps) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        
        #Removes AppxPackages
        #Credit to /u/GavinEke for a modified version of my whitelist code
        [regex]$WhitelistedApps = '|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|Microsoft.XboxGameCallableUI|Microsoft.Xbox.TCUI|Microsoft.XboxIdentityProvider|Microsoft.MSPaint*'
        Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage
        Get-AppxPackage | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps} | Remove-AppxProvisionedPackage -Online
} else {
    Write-Output "Bloatware apps won't be uninstalled. You must be crazy if you don't uninstall them though."
}

#Removes Office related apps
Write-Output "Do you want to remove Office-related apps? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y"){
    $OfficeApps = @(
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.Office.OneNote"               # MS Office One Note
    "Microsoft.Office.Sway"
    )
    foreach ($App in $OfficeApps) {
        Write-Verbose -Message ('Removing Package {0}' -f $App)
        Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }

} else {
    Write-Output "Ok champ"
}

#Removes Microsoft Edge background tasks
Remove-ItemProperty -Path "HKLM:Software\Wow6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\Commands\on-logon-autolaunch" -Name "CommandLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\Commands\on-logon-startup-boost" -Name "CommandLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\Commands\on-logon-autolaunch" -Name "CommandLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\Commands\on-logon-startup-boost" -Name "CommandLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\Commands\on-os-upgrade" -Name "CommandLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name "location"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name "UninstallString"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name "DowngradeCleanupCommand"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Name "LastInstallerSuccessLaunchCmdLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" -Name "AppPath"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate" -Name "path"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\EdgeUpdate" -Name "UninstallCmdLine"
Remove-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" -Name "ModifyPath"

Write-Output "Do you want to install WinGet? (y/n)"
$confirm = Read-Host
if($confirm -eq "y"){
    <#PSScriptInfo

.VERSION 4.1.3

.GUID 3b581edb-5d90-4fa1-ba15-4f2377275463

.AUTHOR asheroto, 1ckov, MisterZeus, ChrisTitusTech, uffemcev, MatthiasGuelck, o-l-a-v

.COMPANYNAME asheroto

.TAGS PowerShell Windows winget win get install installer fix script setup

.PROJECTURI https://github.com/asheroto/winget-install

.RELEASENOTES
[Version 0.0.1] - Initial Release.
[Version 0.0.2] - Implemented function to get the latest version of winget and its license.
[Version 0.0.3] - Signed file for PSGallery.
[Version 0.0.4] - Changed URI to grab latest release instead of releases and preleases.
[Version 0.0.5] - Updated version number of dependencies.
[Version 1.0.0] - Major refactor code, see release notes for more information.
[Version 1.0.1] - Fixed minor bug where version 2.8 was hardcoded in URL.
[Version 1.0.2] - Hardcoded UI Xaml version 2.8.4 as a failsafe in case the API fails. Added CheckForUpdates, Version, Help functions. Various bug fixes.
[Version 1.0.3] - Added error message to catch block. Fixed bug where appx package was not being installed.
[Version 1.0.4] - MisterZeus optimized code for readability.
[Version 2.0.0] - Major refactor. Reverted to UI.Xaml 2.7.3 for stability. Adjusted script to fix install issues due to winget changes (thank you ChrisTitusTech). Added in all architecture support.
[Version 2.0.1] - Renamed repo and URL references from winget-installer to winget-install. Added extra space after the last line of output.
[Version 2.0.2] - Adjusted CheckForUpdates to include Install-Script instructions and extra spacing.
[Version 2.1.0] - Added alternate method/URL for dependencies in case the main URL is down. Fixed licensing issue when winget is installed on Server 2022.
[Version 2.1.1] - Switched primary/alternate methods. Added Cleanup function to avoid errors when cleaning up temp files. Added output of URL for alternate method. Suppressed Add-AppxProvisionedPackage output. Improved success message. Improved verbiage. Improve PS script comments. Added check if the URL is empty. Moved display of URL beneath the check.
[Version 3.0.0] - Major changes. Added OS version detection checks - detects OS version, release ID, ensures compatibility. Forces older file installation for Server 2022 to avoid issues after installing. Added DebugMode, DisableCleanup, Force. Renamed CheckForUpdates to CheckForUpdate. Improved output. Improved error handling. Improved comments. Improved code readability. Moved CheckForUpdate into function. Added PowerShellGalleryName. Renamed Get-OSVersion to Get-OSInfo. Moved architecture detection into Get-OSInfo. Renamed Get-NewestLink to Get-WingetDownloadUrl. Have Get-WingetDownloadUrl not get preview releases.
[Version 3.0.1] - Updated Get-OSInfo function to fix issues when used on non-English systems. Improved error handling of "resources in use" error.
[Version 3.0.2] - Added winget registration command for Windows 10 machines.
[Version 3.1.0] - Added support for one-line installation with irm and iex compatible with $Force session variable. Added UpdateSelf command to automatically update the script to the latest version. Created short URL asheroto.com/winget.
[Version 3.1.1] - Changed winget register command to run on all OS versions.
[Version 3.2.0] - Added -ForceClose logic to relaunch the script in conhost.exe and automatically end active processes associated with winget that could interfere with the installation. Improved verbiage on winget already installed.
[Version 3.2.1] - Fixed minor glitch when using -Version or -Help parameters.
[Version 3.2.2] - Improved script exit functionality.
[Version 3.2.3] - Improved -ForceClose window handling with x86 PowerShell process.
[Version 3.2.4] - Improved verbiage for incompatible systems. Added importing Appx module on Windows Server with PowerShell 7+ systems to avoid error message.
[Version 3.2.5] - Removed pause after script completion. Added optional Wait parameter to force script to wait several seconds for script output.
[Version 3.2.6] - Improved ExitWithDelay function. Sometimes PowerShell will close the window accidentally, even when using the proper 'exit' command. Adjusted several closures for improved readability. Improved error code checking. Fixed glitch with -Wait param.
[Version 3.2.7] - Addded ability to install for all users. Added checks for Windows Sandbox and administrative privileges.
[Version 4.0.0] - Microsoft created some short URLs for winget. Removed a large portion of the script to use short URLs instead. Simplified and refactored. Switched debug param from DebugMode to Debug.
[Version 4.0.1] - Fixed PowerShell help information.
[Version 4.0.2] - Adjusted UpdateSelf function to reset PSGallery to original state if it was not trusted. Improved comments.
[Version 4.0.3] - Updated UI.Xaml package as per winget-cli issue #4208.
[Version 4.0.4] - Fixed detection for Windows multi-session.
[Version 4.0.5] - Improved error handling when registering winget.
[Version 4.1.0] - Support for Windows Server 2019 added by installing Visual C++ Redistributable.
[Version 4.1.1] - Minor revisions to comments & debug output.
[Version 4.1.2] - Implemented Visual C++ Redistributable version detection to ensure compatibility with winget.
[Version 4.1.3] - Added additional debug output for Visual C++ Redistributable version detection.

#>

<#
.SYNOPSIS
	Downloads and installs the latest version of winget and its dependencies.
.DESCRIPTION
	Downloads and installs the latest version of winget and its dependencies.

This script is designed to be straightforward and easy to use, removing the hassle of manually downloading, installing, and configuring winget. This function should be run with administrative privileges.
.EXAMPLE
	winget-install
.PARAMETER Debug
    Enables debug mode, which shows additional information for debugging.
.PARAMETER Force
    Ensures installation of winget and its dependencies, even if already present.
.PARAMETER ForceClose
    Relaunches the script in conhost.exe and automatically ends active processes associated with winget that could interfere with the installation.
.PARAMETER Wait
    Forces the script to wait several seconds before exiting.
.PARAMETER UpdateSelf
    Updates the script to the latest version on PSGallery.
.PARAMETER CheckForUpdate
    Checks if there is an update available for the script.
.PARAMETER Version
    Displays the version of the script.
.PARAMETER Help
    Displays the full help information for the script.
.NOTES
	Version      : 4.1.3
	Created by   : asheroto
.LINK
	Project Site: https://github.com/asheroto/winget-install
#>
[CmdletBinding()]
param (
    [switch]$Force,
    [switch]$ForceClose,
    [switch]$CheckForUpdate,
    [switch]$Wait,
    [switch]$UpdateSelf,
    [switch]$Version,
    [switch]$Help
)

# Script information
$CurrentVersion = '4.1.3'
$RepoOwner = 'asheroto'
$RepoName = 'winget-install'
$PowerShellGalleryName = 'winget-install'

# Preferences
$ProgressPreference = 'SilentlyContinue' # Suppress progress bar (makes downloading super fast)
$ConfirmPreference = 'None' # Suppress confirmation prompts

# Display version if -Version is specified
if ($Version.IsPresent) {
    $CurrentVersion
    exit 0
}

# Display full help if -Help is specified
if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Source -Full
    exit 0
}

# Display $PSVersionTable and Get-Host if -Verbose is specified
if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $PSVersionTable
    Get-Host
}

# Set debug preferences if -Debug is specified
if ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug']) {
    $DebugPreference = 'Continue'
    $ConfirmPreference = 'None'
}

function Get-OSInfo {
    <#
        .SYNOPSIS
        Retrieves detailed information about the operating system version and architecture.

        .DESCRIPTION
        This function queries both the Windows registry and the Win32_OperatingSystem class to gather comprehensive information about the operating system. It returns details such as the release ID, display version, name, type (Workstation/Server), numeric version, edition ID, version (object that includes major, minor, and build numbers), and architecture (OS architecture, not processor architecture).

        .EXAMPLE
        Get-OSInfo

        This example retrieves the OS version details of the current system and returns an object with properties like ReleaseId, DisplayVersion, Name, Type, NumericVersion, EditionId, Version, and Architecture.

        .EXAMPLE
        (Get-OSInfo).Version.Major

        This example retrieves the major version number of the operating system. The Get-OSInfo function returns an object with a Version property, which itself is an object containing Major, Minor, and Build properties. You can access these sub-properties using dot notation.

        .EXAMPLE
        $osDetails = Get-OSInfo
        Write-Output "OS Name: $($osDetails.Name)"
        Write-Output "OS Type: $($osDetails.Type)"
        Write-Output "OS Architecture: $($osDetails.Architecture)"

        This example stores the result of Get-OSInfo in a variable and then accesses various properties to print details about the operating system.
    #>
    [CmdletBinding()]
    param ()

    try {
        # Get registry values
        $registryValues = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $releaseIdValue = $registryValues.ReleaseId
        $displayVersionValue = $registryValues.DisplayVersion
        $nameValue = $registryValues.ProductName
        $editionIdValue = $registryValues.EditionId

        # Strip out "Server" from the $editionIdValue if it exists
        $editionIdValue = $editionIdValue -replace "Server", ""

        # Get OS details using Get-CimInstance because the registry key for Name is not always correct with Windows 11
        $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem
        $nameValue = $osDetails.Caption

        # Get architecture details of the OS (not the processor)
        # Get only the numbers
        $architecture = ($osDetails.OSArchitecture -replace "[^\d]").Trim()

        # If 32-bit or 64-bit replace with x32 and x64
        if ($architecture -eq "32") {
            $architecture = "x32"
        } elseif ($architecture -eq "64") {
            $architecture = "x64"
        }

        # Get OS version details (as version object)
        $versionValue = [System.Environment]::OSVersion.Version

        # Determine product type
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.producttype?view=powershellsdk-1.1.0
        if ($osDetails.ProductType -eq 1) {
            $typeValue = "Workstation"
        } elseif ($osDetails.ProductType -eq 2 -or $osDetails.ProductType -eq 3) {
            $typeValue = "Server"
        } else {
            $typeValue = "Unknown"
        }

        # Extract numerical value from Name
        $numericVersion = ($nameValue -replace "[^\d]").Trim()

        # If the numeric version is 10 or above, and the caption contains "multi-session", consider it a workstation
        if ($numericVersion -ge 10 -and $osDetails.Caption -match "multi-session") {
            $typeValue = "Workstation"
        }

        # Create and return custom object with the required properties
        $result = [PSCustomObject]@{
            ReleaseId      = $releaseIdValue
            DisplayVersion = $displayVersionValue
            Name           = $nameValue
            Type           = $typeValue
            NumericVersion = $numericVersion
            EditionId      = $editionIdValue
            Version        = $versionValue
            Architecture   = $architecture
        }

        return $result
    } catch {
        Write-Error "Unable to get OS version details.`nError: $_"
        ExitWithDelay 1
    }
}

function Get-GitHubRelease {
    <#
        .SYNOPSIS
        Fetches the latest release information of a GitHub repository.

        .DESCRIPTION
        This function uses the GitHub API to get information about the latest release of a specified repository, including its version and the date it was published.

        .PARAMETER Owner
        The GitHub username of the repository owner.

        .PARAMETER Repo
        The name of the repository.

        .EXAMPLE
        Get-GitHubRelease -Owner "asheroto" -Repo "winget-install"
        This command retrieves the latest release version and published datetime of the winget-install repository owned by asheroto.
    #>
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        $latestVersion = $response.tag_name
        $publishedAt = $response.published_at

        # Convert UTC time string to local time
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()

        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Unable to check for updates.`nError: $_"
        exit 1
    }
}

function CheckForUpdate {
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [version]$CurrentVersion,
        [string]$PowerShellGalleryName
    )

    $Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

    Write-Output ""
    Write-Output ("Repository:       {0,-40}" -f "https://github.com/$RepoOwner/$RepoName")
    Write-Output ("Current Version:  {0,-40}" -f $CurrentVersion)
    Write-Output ("Latest Version:   {0,-40}" -f $Data.LatestVersion)
    Write-Output ("Published at:     {0,-40}" -f $Data.PublishedDateTime)

    if ($Data.LatestVersion -gt $CurrentVersion) {
        Write-Output ("Status:           {0,-40}" -f "A new version is available.")
        Write-Output "`nOptions to update:"
        Write-Output "- Download latest release: https://github.com/$RepoOwner/$RepoName/releases"
        if ($PowerShellGalleryName) {
            Write-Output "- Run: $RepoName -UpdateSelf"
            Write-Output "- Run: Install-Script $PowerShellGalleryName -Force"
        }
    } else {
        Write-Output ("Status:           {0,-40}" -f "Up to date.")
    }
    exit 0
}

function UpdateSelf {
    try {
        # Get PSGallery version of script
        $psGalleryScriptVersion = (Find-Script -Name $PowerShellGalleryName).Version

        # If the current version is less than the PSGallery version, update the script
        if ($CurrentVersion -lt $psGalleryScriptVersion) {
            Write-Output "Updating script to version $psGalleryScriptVersion..."

            # Install NuGet PackageProvider if not already installed
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name "NuGet" -Force
            }

            # Trust the PSGallery if not already trusted
            $psRepoInstallationPolicy = (Get-PSRepository -Name 'PSGallery').InstallationPolicy
            if ($psRepoInstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted | Out-Null
            }

            # Update the script
            Install-Script $PowerShellGalleryName -Force

            # If PSGallery was not trusted, reset it to its original state
            if ($psRepoInstallationPolicy -ne 'Trusted') {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy $psRepoInstallationPolicy | Out-Null
            }

            Write-Output "Script updated to version $psGalleryScriptVersion."
            exit 0
        } else {
            Write-Output "Script is already up to date."
            exit 0
        }
    } catch {
        Write-Output "An error occurred: $_"
        exit 1
    }
}

function Write-Section($text) {
    <#
        .SYNOPSIS
        Prints a text block surrounded by a section divider for enhanced output readability.

        .DESCRIPTION
        This function takes a string input and prints it to the console, surrounded by a section divider made of hash characters.
        It is designed to enhance the readability of console output.

        .PARAMETER text
        The text to be printed within the section divider.

        .EXAMPLE
        Write-Section "Downloading Files..."
        This command prints the text "Downloading Files..." surrounded by a section divider.
    #>
    Write-Output ""
    Write-Output ("#" * ($text.Length + 4))
    Write-Output "# $text #"
    Write-Output ("#" * ($text.Length + 4))
    Write-Output ""
}

function Get-WingetDownloadUrl {
    <#
        .SYNOPSIS
        Retrieves the download URL of the latest release asset that matches a specified pattern from the GitHub repository.

        .DESCRIPTION
        This function uses the GitHub API to get information about the latest release of the winget-cli repository.
        It then retrieves the download URL for the release asset that matches a specified pattern.

        .PARAMETER Match
        The pattern to match in the asset names.

        .EXAMPLE
        Get-WingetDownloadUrl "msixbundle"
        This command retrieves the download URL for the latest release asset with a name that contains "msixbundle".
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Match
    )

    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"
    $releases = Invoke-RestMethod -uri $uri -Method Get -ErrorAction Stop

    Write-Debug "Getting latest release..."
    foreach ($release in $releases) {
        if ($release.name -match "preview") {
            continue
        }
        $data = $release.assets | Where-Object name -Match $Match
        if ($data) {
            return $data.browser_download_url
        }
    }

    Write-Debug "Falling back to the latest release..."
    $latestRelease = $releases | Select-Object -First 1
    $data = $latestRelease.assets | Where-Object name -Match $Match
    return $data.browser_download_url
}

function Get-WingetStatus {
    <#
        .SYNOPSIS
        Checks if winget is installed.

        .DESCRIPTION
        This function checks if winget is installed.

        .EXAMPLE
        Get-WingetStatus
    #>

    # Check if winget is installed
    $winget = Get-Command -Name winget -ErrorAction SilentlyContinue

    # If winget is installed, return $true
    if ($null -ne $winget) {
        return $true
    }

    # If winget is not installed, return $false
    return $false
}

function Handle-Error {
    <#
        .SYNOPSIS
            Handles common errors that may occur during an installation process.

        .DESCRIPTION
            This function takes an ErrorRecord object and checks for certain known error codes.
            Depending on the error code, it writes appropriate warning messages or throws the error.

        .PARAMETER ErrorRecord
            The ErrorRecord object that represents the error that was caught. This object contains
            information about the error, including the exception that was thrown.

        .EXAMPLE
            try {
                # Some code that may throw an error...
            } catch {
                Handle-Error $_
            }
            This example shows how you might use the Handle-Error function in a try-catch block.
            If an error occurs in the try block, the catch block catches it and calls Handle-Error,
            passing the error (represented by the $_ variable) to the function.
    #>
    param($ErrorRecord)

    # Store current value
    $OriginalErrorActionPreference = $ErrorActionPreference

    # Set to silently continue
    $ErrorActionPreference = 'SilentlyContinue'

    # Handle common errors
    # Not returning $ErrorRecord on some errors is intentional
    if ($ErrorRecord.Exception.Message -match '0x80073D06') {
        Write-Warning "Higher version already installed."
        Write-Warning "That's okay, continuing..."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF0') {
        Write-Warning "Same version already installed."
        Write-Warning "That's okay, continuing..."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073D02') {
        # Stop execution and return the ErrorRecord so that the calling try/catch block throws the error
        Write-Warning "Resources modified are in-use. Try closing Windows Terminal / PowerShell / Command Prompt and try again."
        Write-Warning "Windows Terminal sometimes has trouble installing winget. If you are using Windows Terminal and the problem persists, run the script with the -ForceClose parameter which will relaunch the script in conhost.exe and automatically end active processes associated with winget that could interfere with the installation. Please note that using the -ForceClose parameter will close the PowerShell window and could break custom scripts that rely on the current PowerShell session."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF3') {
        # Prerequisite not detected, tell user to run it again
        Write-Warning "Problem with one of the prerequisites."
        Write-Warning "Try running the script again which usually fixes the issue. If the problem persists, try running the script with the -ForceClose parameter which will relaunch the script in conhost.exe and automatically end active processes associated with winget that could interfere with the installation. Please note that using the -ForceClose parameter will close the PowerShell window and could break custom scripts that rely on the current PowerShell session."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF9') {
        Write-Warning "Registering winget failed with error code 0x80073CF9."
        Write-Warning "This error usually occurs when using the Local System account to install winget. The SYSTEM account is not officially supported by winget and may not work. See the requirements section of the README. If winget is not working, run the installation script again using an Administrator account."
    } elseif ($ErrorRecord.Exception.Message -match 'Unable to connect to the remote server') {
        Write-Warning "Cannot connect to the Internet to download the required files."
        Write-Warning "Try running the script again and make sure you are connected to the Internet."
        Write-Warning "Sometimes the nuget.org server is down, so you may need to try again later."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match "The remote name could not be resolved") {
        Write-Warning "Cannot connect to the Internet to download the required files."
        Write-Warning "Try running the script again and make sure you are connected to the Internet."
        Write-Warning "Make sure DNS is working correctly on your computer."
    } else {
        # For other errors, we should stop the execution and return the ErrorRecord so that the calling try/catch block throws the error
        return $ErrorRecord
    }

    # Reset to original value
    $ErrorActionPreference = $OriginalErrorActionPreference
}

function Get-CurrentProcess {
    <#
        .SYNOPSIS
            Retrieves the current PowerShell process information.

        .DESCRIPTION
            The Get-CurrentProcess function identifies the current PowerShell process by temporarily changing the console window title. It then filters the list of running processes to find the one with the matching window title. The function returns a custom object containing the Name and Id of the current process.

        .EXAMPLE
            PS C:\> $result = Get-CurrentProcess
            PS C:\> Write-Output $result

            This example demonstrates how to call the Get-CurrentProcess function and store its output in a variable named $result. The output is then displayed using Write-Output.

        .NOTES
            The function temporarily changes the console window title. Ensure no other scripts or processes are dependent on the window title during execution. The function uses a 1-second sleep to allow time for the window title change to take effect. This may vary based on system performance.
    #>
    $oldTitle = $host.ui.RawUI.WindowTitle
    $tempTitle = ([Guid]::NewGuid())
    $host.ui.RawUI.WindowTitle = $tempTitle
    Start-Sleep 1
    $currentProcess = Get-Process | Where-Object { $_.MainWindowTitle -eq $tempTitle }
    $currentProcess = [PSCustomObject]@{
        Name = $currentProcess.Name
        Id   = $currentProcess.Id
    }
    $host.ui.RawUI.WindowTitle = $oldTitle
    return $currentProcess
}

function ExitWithDelay {
    <#
        .SYNOPSIS
            Exits the script with a specified exit code after a specified delay, 10 seconds by default.

        .DESCRIPTION
            This function takes an exit code as an argument, waits for 10 seconds unless specified, and then exits the script with the given exit code.

        .PARAMETER ExitCode
            The exit code to use when exiting the script.

        .EXAMPLE
            ExitWithDelay -ExitCode 1
            Waits for 10 seconds (default) and then exits the script with an exit code of 1.

        .EXAMPLE
            ExitWithDelay -ExitCode 2 -Seconds 5
            Waits for 5 seconds and then exits the script with an exit code of 2.
        .NOTES
            Use this function to introduce a delay before exiting the script, allowing time for any cleanup or logging activities.
    #>

    param (
        [int]$ExitCode,
        [int]$Seconds = 10
    )

    # Debug mode output
    if ($Debug -and $Wait) {
        Write-Warning "Wait specified, waiting several seconds..."
    } elseif ($Debug -and !$Wait) {
        Write-Warning "Wait not specified, exiting immediately..."
    }

    # If Wait is specified, wait for x seconds before exiting
    if ($Wait) {
        # Waiting for x seconds output
        Write-Output "`nWaiting for $Seconds seconds before exiting..."
        Start-Sleep -Seconds $Seconds
    }

    # Exit the script with error code
    # Some systems may accidentally close the window, but that's a PowerShell bug
    # https://stackoverflow.com/questions/67593504/why-wont-the-exit-function-work-in-my-powershell-code
    Exit $ExitCode
}

function Import-GlobalVariable {
    <#
        .SYNOPSIS
        This function checks if a specified global variable exists and imports its value into a script scope variable of the same name.

        .DESCRIPTION
        The Import-GlobalVariable function allows you to specify the name of a variable. It checks if a global variable with that name exists, and if it does, it imports its value into a script scope variable with the same name.

        .PARAMETER VariableName
        The name of the variable to check and import if it exists in the global scope.

    #>

    [CmdletBinding()]
    param(
        [string]$VariableName
    )

    # Check if the specified global variable exists; if yes, import its value
    try {
        $globalValue = Get-Variable -Name $VariableName -ValueOnly -Scope Global -ErrorAction Stop
        Set-Variable -Name $VariableName -Value $globalValue -Scope Script
    } catch {
        # If the variable does not exist, do nothing
    }
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Checks if the script is running with Administrator privileges. Returns $true if running with Administrator privileges, $false otherwise.

    .DESCRIPTION
        This function checks if the current PowerShell session is running with Administrator privileges by examining the role of the current user. It returns $true if the current user is an Administrator, $false otherwise.

    .EXAMPLE
        Test-AdminPrivileges

    .NOTES
        This function is particularly useful for scripts that require elevated permissions to run correctly.
    #>
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $true
    }
    return $false
}

Function New-TemporaryFile2 {
    <#
    .SYNOPSIS
        Creates a new temporary file.

    .DESCRIPTION
        This function generates a temporary file and returns the full path of the file. The New-TemporaryFile command is not available in PowerShell 5.1 and earlier so this function is a workaround.

    .EXAMPLE
        $tempFile = New-TemporaryFile2
        This example creates a new temporary file and stores its path in the $tempFile variable.

    .OUTPUTS
        String. The full path of the created temporary file.
    #>

    # Create a temporary file
    $tempPath = [System.IO.Path]::GetTempPath()
    $tempFile = [System.IO.Path]::Combine($tempPath, [System.IO.Path]::GetRandomFileName())
    $null = New-Item -Path $tempFile -ItemType File -Force

    # Return the path of the temporary file
    return $tempFile
}

function Add-ToEnvironmentPath {
    param (
        [string]$PathToAdd
    )
    <#
    .SYNOPSIS
    Adds the specified path to the environment PATH variable.

    .DESCRIPTION
    This function adds a given path to the system-wide and current session PATH environment variable if it is not already present.

    .PARAMETER PathToAdd
    The directory path to add to the environment PATH variable.

    .EXAMPLE
    Add-ToEnvironmentPath -PathToAdd "C:\Program Files\MyApp"
    #>

    # Get the full path to ensure consistency
    $fullPathToAdd = [System.IO.Path]::GetFullPath($PathToAdd)

    # Get the current system PATH
    $systemEnvPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)

    # Check if the path is already in the system PATH variable
    if (-not ($systemEnvPath -split ';').Contains($fullPathToAdd)) {
        # Add to system PATH
        $systemEnvPath += ";$fullPathToAdd"
        [System.Environment]::SetEnvironmentVariable('PATH', $systemEnvPath, [System.EnvironmentVariableTarget]::Machine)
        Write-Output "Adding winget folder to the system PATH."
        Write-Debug "Adding $fullPathToAdd to the system PATH.`n`n"
    } else {
        Write-Output "winget folder already in the system PATH."
        Write-Debug "$fullPathToAdd is already in the system PATH.`n`n"
    }

    # Update the current session PATH
    if (-not ($env:PATH -split ';').Contains($fullPathToAdd)) {
        $env:PATH += ";$fullPathToAdd"
        Write-Output "Adding winget folder to the current session PATH."
        Write-Debug "Adding $fullPathToAdd to the current session PATH."
    } else {
        Write-Output "winget folder is already in the current session PATH."
        Write-Debug "$fullPathToAdd is already in the current session PATH."
    }
}

function Test-VCRedistInstalled {
    <#
    .SYNOPSIS
    Checks if Visual C++ Redistributable is installed and verifies the major version is 14.

    .DESCRIPTION
    This function checks the registry and the file system to determine if Visual C++ Redistributable is installed
    and if the major version is 14.

    .EXAMPLE
    Test-VCRedistInstalled
    #>

    # Assets
    $64BitOS = [System.Environment]::Is64BitOperatingSystem
    $64BitProcess = [System.Environment]::Is64BitProcess

    # Require running system native process
    if ($64BitOS -and -not $64BitProcess) {
        Throw 'Please run PowerShell in the system native architecture (x64 PowerShell if x64 Windows).'
    }

    # Check that uninstall information exists in the registry
    $registryPath = [string]::Format(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\{0}\Microsoft\VisualStudio\14.0\VC\Runtimes\X{1}',
        $(if ($64BitOS -and $64BitProcess) { 'WOW6432Node' } else { '' }),
        $(if ($64BitOS) { '64' } else { '86' })
    )

    $registryExists = Test-Path -Path $registryPath

    Write-Debug "Registry Path: $registryPath"
    Write-Debug "Registry Exists: $registryExists"

    # Check the major version
    $majorVersion = if ($registryExists) {
        (Get-ItemProperty -Path $registryPath -Name 'Major').Major
    } else {
        0
    }

    # Check the full version
    $version = if ($registryExists) {
        (Get-ItemProperty -Path $registryPath -Name 'Version').Version
    } else {
        0
    }

    Write-Debug "Major Version: $majorVersion"
    Write-Debug "Version: $version"

    # Check that one required DLL exists on the file system
    $dllPath = [string]::Format(
        '{0}\system32\concrt140.dll',
        $env:windir
    )

    $dllExists = [System.IO.File]::Exists($dllPath)

    Write-Debug "DLL Path: $dllPath"
    Write-Debug "DLL Exists: $dllExists"

    # Determine if VCRedist is installed and major version is 14
    return $registryExists -and $majorVersion -eq 14 -and $dllExists
}

function TryRemove {
    <#
    .SYNOPSIS
    Tries to remove a specified file if it exists.

    .DESCRIPTION
    This function checks if the specified file exists and attempts to remove it. 
    It will not produce an error if the file does not exist or if the removal fails.

    .PARAMETER FilePath
    The path to the file that should be removed.

    .EXAMPLE
    TryRemove -FilePath "C:\path\to\file.txt"
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        if (Test-Path -Path $FilePath) {
            Remove-Item -Path $FilePath -ErrorAction SilentlyContinue
            if ($?) {
                Write-Debug "File '$FilePath' was successfully removed."
            } else {
                Write-Debug "Failed to remove the file '$FilePath'."
            }
        } else {
            Write-Debug "File '$FilePath' does not exist."
        }
    } catch {
        Write-Debug "An error occurred while trying to remove the file '$FilePath'."
    }
}

# ============================================================================ #
# Initial checks
# ============================================================================ #

# Use global variables if specified by user
Import-GlobalVariable -VariableName "Debug"
Import-GlobalVariable -VariableName "ForceClose"
Import-GlobalVariable -VariableName "Force"

# First heading
Write-Output "winget-install $CurrentVersion"

# Check for updates if -CheckForUpdate is specified
if ($CheckForUpdate) { CheckForUpdate -RepoOwner $RepoOwner -RepoName $RepoName -CurrentVersion $CurrentVersion -PowerShellGalleryName $PowerShellGalleryName }

# Update the script if -UpdateSelf is specified
if ($UpdateSelf) { UpdateSelf }

# Heading
Write-Output "To check for updates, run winget-install -CheckForUpdate"
Write-Output "To delay script exit, run winget-install -Wait"

# Check if the current user is an administrator
if (-not (Test-AdminPrivileges)) {
    Write-Warning "winget requires Administrator privileges to install. Please run the script as an Administrator and try again."
    ExitWithDelay 1
}

# Get OS version
$osVersion = Get-OSInfo

# Get architecture type
$arch = $osVersion.Architecture

# Get current process module name to determine if launched in conhost
$currentProcess = Get-CurrentProcess

# If it's a workstation, make sure it is Windows 10+
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -lt 10) {
    Write-Error "winget requires Windows 10 or later on workstations. Your version of Windows is not supported."
    ExitWithDelay 1
}

# If it's a workstation with Windows 10, make sure it's version 1809 or greater
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10 -and $osVersion.ReleaseId -lt 1809) {
    Write-Error "winget requires Windows 10 version 1809 or later on workstations. Please update Windows to a compatible version."
    ExitWithDelay 1
}

# If it's a server, it needs to be 2019+
if ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -lt 2019) {
    Write-Error "winget requires Windows Server 2019 or newer on server platforms. Your version of Windows Server is not supported."
    ExitWithDelay 1
}

# Check if winget is already installed
if (Get-WingetStatus) {
    if ($Force -eq $false) {
        Write-Warning "winget is already installed, exiting..."
        Write-Warning "If you want to reinstall winget, run the script with the -Force parameter."
        ExitWithDelay 0 5
    }
}

# Check if ForceClose parameter is specified. If terminal detected, so relaunch in conhost
if ($ForceClose) {
    Write-Warning "ForceClose parameter is specified."
    if ($currentProcess.Name -eq "WindowsTerminal") {
        Write-Warning "Terminal detected, relaunching in conhost in 10 seconds..."
        Write-Warning "It may break your custom batch files and ps1 scripts with extra commands!"
        Start-Sleep -Seconds 10

        # Prepare the command to relaunch
        $command = "cd '$pwd'; $($MyInvocation.Line)"

        # Append parameters if their corresponding variables are $true and not already in the command
        if ($Force -and !($command -imatch '\s-Force\b')) { $command += " -Force" }
        if ($ForceClose -and !($command -imatch '\s-ForceClose\b')) { $command += " -ForceClose" }
        if ($Debug -and !($command -imatch '\s-Debug\b')) { $command += " -Debug" }

        # Relaunch in conhost
        if ([Environment]::Is64BitOperatingSystem) {
            if ([Environment]::Is64BitProcess) {
                Start-Process -FilePath "conhost.exe" -ArgumentList "powershell -ExecutionPolicy Bypass -Command &{$command}" -Verb RunAs
            } else {
                Start-Process -FilePath "$env:windir\sysnative\conhost.exe" -ArgumentList "powershell -ExecutionPolicy Bypass -Command &{$command}" -Verb RunAs
            }
        } else {
            Start-Process -FilePath "conhost.exe" -ArgumentList "powershell -ExecutionPolicy Bypass -Command &{$command}" -Verb RunAs
        }

        # Stop the current process module
        Stop-Process -id $currentProcess.Id
    } else {
        Write-Warning "Windows Terminal not detected, continuing..."
    }
}

# ============================================================================ #
# Beginning of installation process
# ============================================================================ #

try {
    # ============================================================================ #
    # Install prerequisites
    # ============================================================================ #

    Write-Section "Prerequisites"

    try {
        # Download VCLibs
        $VCLibs_Url = "https://aka.ms/Microsoft.VCLibs.${arch}.14.00.Desktop.appx"
        $VCLibs_Path = New-TemporaryFile2
        Write-Output "Downloading VCLibs..."
        Write-Debug "Downloading VCLibs from $VCLibs_Url to $VCLibs_Path`n`n"
        Invoke-WebRequest -Uri $VCLibs_Url -OutFile $VCLibs_Path

        # Download UI.Xaml
        $UIXaml_Url = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.${arch}.appx"
        $UIXaml_Path = New-TemporaryFile2
        Write-Output "Downloading UI.Xaml..."
        Write-Debug "Downloading UI.Xaml from $UIXaml_Url to $UIXaml_Path"
        Invoke-WebRequest -Uri $UIXaml_Url -OutFile $UIXaml_Path
    } catch {
        $errorHandled = Handle-Error $_
        if ($null -ne $errorHandled) {
            throw $errorHandled
        }
        $errorHandled = $null
    }

    # ============================================================================ #
    #  winget
    # ============================================================================ #

    Write-Section "winget"

    # winget
    try {
        # Download winget license
        $winget_license_path = New-TemporaryFile2
        $winget_license_url = Get-WingetDownloadUrl -Match "License1.xml"
        Write-Output "Downloading winget license..."
        Write-Debug "Downloading winget license from $winget_license_url to $winget_license_path`n`n"
        Invoke-WebRequest -Uri $winget_license_url -OutFile $winget_license_path

        # Download winget
        $winget_path = New-TemporaryFile2
        $winget_url = "https://aka.ms/getwinget"
        Write-Output "Downloading winget..."
        Write-Debug "Downloading winget from $winget_url to $winget_path`n`n"
        Invoke-WebRequest -Uri $winget_url -OutFile $winget_path

        # Install everything
        Write-Output "Installing winget and its dependencies..."
        Add-AppxProvisionedPackage -Online -PackagePath $winget_path -DependencyPackagePath $UIXaml_Path, $VCLibs_Path -LicensePath $winget_license_path | Out-Null

        # Remove temporary files
        Write-Debug "Removing temporary files..."
        TryRemove $VCLibs_Path
        TryRemove $UIXaml_Path
        TryRemove $winget_path
        TryRemove $winget_license_path
    } catch {
        $errorHandled = Handle-Error $_
        if ($null -ne $errorHandled) {
            throw $errorHandled
        }
        $errorHandled = $null
    }

    # ============================================================================ #
    #  Server 2019 only
    # ============================================================================ #

    if ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -eq 2019) {
        # ============================================================================ #
        # Visual C++ Redistributable
        # ============================================================================ #

        Write-Section "Visual C++ Redistributable (Server 2019 only)"

        # Test if Visual C++ Redistributable is not installed
        if (!(Test-VCRedistInstalled)) {
            Write-Debug "Visual C++ Redistributable is not installed.`n`n"

            # Define the URL and temporary file path for the download
            $VCppRedistributable_Url = "https://aka.ms/vs/17/release/vc_redist.${arch}.exe"
            $VCppRedistributable_Path = New-TemporaryFile2
            Write-Output "Downloading Visual C++ Redistributable..."
            Write-Debug "Downloading Visual C++ Redistributable from $VCppRedistributable_Url to $VCppRedistributable_Path`n`n"
            Invoke-WebRequest -Uri $VCppRedistributable_Url -OutFile $VCppRedistributable_Path

            # Rename file
            $VCppRedistributableExe_Path = $VCppRedistributable_Path + ".exe"
            Rename-Item -Path $VCppRedistributable_Path -NewName $VCppRedistributableExe_Path

            # Install Visual C++ Redistributable
            Write-Output "Installing Visual C++ Redistributable..."
            Write-Debug "Installing Visual C++ Redistributable from $VCppRedistributableExe_Path`n`n"
            Start-Process -FilePath $VCppRedistributableExe_Path -ArgumentList "/install", "/quiet", "/norestart" -Wait

            Write-Debug "Removing temporary file..."
            TryRemove $VCppRedistributableExe_Path
        } else {
            Write-Output "Visual C++ Redistributable is already installed."
        }

        # ============================================================================ #
        # Adjust access rights & PATH environment variable
        # ============================================================================ #

        Write-Section "Adjust access rights & PATH environment variable (Server 2019 only)"

        # Find the last version of WinGet folder path
        $WinGetFolderPath = Get-ChildItem -Path ([IO.Path]::Combine($env:ProgramFiles, 'WindowsApps')) -Filter "Microsoft.DesktopAppInstaller_*_${arch}__8wekyb3d8bbwe" | Sort-Object Name | Select-Object -Last 1
        Write-Debug "WinGetFolderPath: $WinGetFolderPath`n`n"

        if ($null -ne $WinGetFolderPath) {
            $WinGetFolderPath = $WinGetFolderPath.FullName
            # Fix Permissions
            Write-Output "Fixing permissions for $WinGetFolderPath..."
            $acl = Get-Acl $WinGetFolderPath
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $WinGetFolderPath -AclObject $acl

            # Add Environment Path
            Add-ToEnvironmentPath -PathToAdd $WinGetFolderPath
        } else {
            Write-Warning "winget folder path not found. You may need to manually add winget's folder path to your system PATH environment variable."
        }
    }

    # ============================================================================ #
    #  Done
    # ============================================================================ #

    Write-Section "Complete"

    Write-Output "winget installed successfully."

    # ============================================================================ #
    # Finished
    # ============================================================================ #

    # Timeout before checking winget
    Write-Output "Checking if winget is installed and working..."
    Start-Sleep -Seconds 3

    # Check if winget is installed
    if (Get-WingetStatus -eq $true) {
        Write-Output "winget is installed and working now, you can go ahead and use it."
    } else {
        # ============================================================================ #
        # Register winget
        # ============================================================================ #

        # If winget is not detected as a command, try registering it
        Write-Section "Registering"
        try {
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
            Write-Output "winget command registered successfully."
        } catch {
            Write-Warning "Unable to register winget. You may need to restart your computer for winget to work."
            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) {
                throw $errorHandled
            }
            $errorHandled = $null
        }

        # If winget is still not detected as a command, show warning
        if (Get-WingetStatus -eq $false) {
            Write-Warning "winget is installed but is not detected as a command. Try using winget now. If it doesn't work, wait about 1 minute and try again (it is sometimes delayed). Also try restarting your computer."
            Write-Warning "If you restart your computer and the command still isn't recognized, please read the Troubleshooting section`nof the README: https://github.com/asheroto/winget-install#troubleshooting`n"
            Write-Warning "Make sure you have the latest version of the script by running this command: $PowerShellGalleryName -CheckForUpdate`n`n"
        }
    }

    ExitWithDelay 0
} catch {
    # ============================================================================ #
    # Error handling
    # ============================================================================ #

    Write-Section "WARNING! An error occurred during installation!"
    Write-Warning "If messages above don't help and the problem persists, please read the Troubleshooting section`nof the README: https://github.com/asheroto/winget-install#troubleshooting"
    Write-Warning "Make sure you have the latest version of the script by running this command: $PowerShellGalleryName -CheckForUpdate`n`n"

    # If it's not 0x80073D02 (resources in use), show error
    if ($_.Exception.Message -notmatch '0x80073D02') {
        if ($Debug) {
            Write-Warning "Line number : $($_.InvocationInfo.ScriptLineNumber)"
        }
        Write-Warning "Error: $($_.Exception.Message)`n"
    }

    ExitWithDelay 1
}
}
else {
    Write-Output "WinGet will not be installed"
}

Write-Output "Do you want to optimize privacy settings? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output 'Windows will never again track you.'
    Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Title-Templates.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Individual-Tweaks.psm1"

# Adapted from: https://youtu.be/qWESrvP_uU8
# Adapted from: https://youtu.be/hQSkPmZRCjc
# Adapted from: https://github.com/ChrisTitusTech/win10script
# Adapted from: https://github.com/Sycnex/Windows10Debloater
# Adapted from: https://github.com/kalaspuffar/windows-debloat

function Optimize-Privacy() {
    [CmdletBinding()]
    param(
        [Switch] $Revert,
        [Int]    $Zero = 0,
        [Int]    $One = 1,
        [Array]  $EnableStatus = @(
            @{ Symbol = "-"; Status = "Disabling"; }
            @{ Symbol = "+"; Status = "Enabling"; }
        )
    )
    $TweakType = "Privacy"

    If ($Revert) {
        Write-Status -Types "*", $TweakType -Status "Reverting the tweaks is set to '$Revert'."
        $Zero = 1
        $One = 0
        $EnableStatus = @(
            @{ Symbol = "*"; Status = "Re-Enabling"; }
            @{ Symbol = "*"; Status = "Re-Disabling"; }
        )
    }

    # Initialize all Path variables used to Registry Tweaks
    $PathToLMAutoLogger = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger"
    $PathToLMDeliveryOptimizationCfg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    $PathToLMPoliciesAdvertisingInfo = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    $PathToLMPoliciesSQMClient = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    $PathToLMPoliciesToWifi = "HKLM:\Software\Microsoft\PolicyManager\default\WiFi"
    $PathToLMPoliciesWindowsUpdate = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $PathToLMWindowsTroubleshoot = "HKLM:\SOFTWARE\Microsoft\WindowsMitigation"
    $PathToCUContentDeliveryManager = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    $PathToCUDeviceAccessGlobal = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
    $PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $PathToCUInputPersonalization = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $PathToCUInputTIPC = "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
    $PathToCUPoliciesCloudContent = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $PathToCUSiufRules = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"

    Write-Title -Text "Privacy Tweaks"
    If (!$Revert) {
        #Disable-ClipboardHistory
        Disable-Cortana
    } Else {
        #Enable-ClipboardHistory
        Enable-Cortana
    }

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) File Explorer Ads (OneDrive, New Features etc.)..."
    Set-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value $Zero

    Write-Section -Text "Personalization"
    Write-Caption -Text "Start & Lockscreen"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Show me the windows welcome experience after updates..."
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Get fun facts and tips, etc. on lock screen'..."

    $ContentDeliveryManagerDisableOnZero = @(
        "SubscribedContent-310093Enabled"
        "SubscribedContent-314559Enabled"
        "SubscribedContent-314563Enabled"
        "SubscribedContent-338387Enabled"
        "SubscribedContent-338388Enabled"
        "SubscribedContent-338389Enabled"
        "SubscribedContent-338393Enabled"
        "SubscribedContent-353698Enabled"
        "RotatingLockScreenOverlayEnabled"
        "RotatingLockScreenEnabled"
        # Prevents Apps from re-installing
        "ContentDeliveryAllowed"
        "FeatureManagementEnabled"
        "OemPreInstalledAppsEnabled"
        "PreInstalledAppsEnabled"
        "PreInstalledAppsEverEnabled"
        "RemediationRequired"
        "SilentInstalledAppsEnabled"
        "SoftLandingEnabled"
        "SubscribedContentEnabled"
        "SystemPaneSuggestionsEnabled"
    )

    Write-Status -Types "?", $TweakType -Status "From Path: $PathToCUContentDeliveryManager"
    ForEach ($Name in $ContentDeliveryManagerDisableOnZero) {
        Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) $($Name): $Zero"
        Set-ItemProperty -Path "$PathToCUContentDeliveryManager" -Name "$Name" -Type DWord -Value $Zero
    }

    Write-Status -Types "-", $TweakType -Status "Disabling 'Suggested Content in the Settings App'..."
    If (Test-Path "$PathToCUContentDeliveryManager\Subscriptions") {
        Remove-Item -Path "$PathToCUContentDeliveryManager\Subscriptions" -Recurse
    }

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Show Suggestions' in Start..."
    If (Test-Path "$PathToCUContentDeliveryManager\SuggestedApps") {
        Remove-Item -Path "$PathToCUContentDeliveryManager\SuggestedApps" -Recurse
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value $One

    Write-Section -Text "Privacy -> Windows Permissions"
    Write-Caption -Text "General"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Let apps use my advertising ID..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value $Zero
    If (!(Test-Path "$PathToLMPoliciesAdvertisingInfo")) {
        New-Item -Path "$PathToLMPoliciesAdvertisingInfo" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesAdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Let websites provide locally relevant content by accessing my language list'..."
    Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value $One

    Write-Caption -Text "Speech"
    If (!$Revert) {
        Disable-OnlineSpeechRecognition
    } Else {
        Enable-OnlineSpeechRecognition
    }

    Write-Caption -Text "Inking & Typing Personalization"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToCUInputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToCUInputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUInputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value $One

    Write-Caption -Text "Diagnostics & Feedback"
    If (!$Revert) {
        Disable-Telemetry
    } Else {
        Enable-Telemetry
    }

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) send inking and typing data to Microsoft..."
    If (!(Test-Path "$PathToCUInputTIPC")) {
        New-Item -Path "$PathToCUInputTIPC" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToCUInputTIPC" -Name "Enabled" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Improve Inking & Typing Recognition..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) View diagnostic data..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" -Name "EnableEventTranscript" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) feedback frequency..."
    If (!(Test-Path "$PathToCUSiufRules")) {
        New-Item -Path "$PathToCUSiufRules" -Force | Out-Null
    }
    If ((Test-Path "$PathToCUSiufRules\PeriodInNanoSeconds")) {
        Remove-ItemProperty -Path "$PathToCUSiufRules" -Name "PeriodInNanoSeconds"
    }
    Set-ItemProperty -Path "$PathToCUSiufRules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value $Zero

    Write-Caption -Text "Activity History"
    If ($Revert) {
        Enable-ActivityHistory
    } Else {
        Disable-ActivityHistory
    }

    Write-Section -Text "Privacy -> Apps Permissions"
    Write-Caption -Text "Location"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value $Zero
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "EnableStatus" -Type DWord -Value $Zero

    Write-Caption -Text "Notifications"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny"

    Write-Caption -Text "App Diagnostics"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny"

    Write-Caption -Text "Account Info Access"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny"

    Write-Caption -Text "Other Devices"
    Write-Status -Types "-", $TweakType -Status "Denying device access..."
    If (!(Test-Path "$PathToCUDeviceAccessGlobal\LooselyCoupled")) {
        New-Item -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Force | Out-Null
    }
    # Disable sharing information with unpaired devices
    Set-ItemProperty -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Name "Value" -Value "Deny"
    ForEach ($key in (Get-ChildItem "$PathToCUDeviceAccessGlobal")) {
        If ($key.PSChildName -EQ "LooselyCoupled") {
            Continue
        }
        Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Setting $($key.PSChildName) value to 'Deny' ..."
        Set-ItemProperty -Path ("$PathToCUDeviceAccessGlobal\" + $key.PSChildName) -Name "Value" -Value "Deny"
    }

    Write-Caption -Text "Background Apps"
    Enable-BackgroundAppsToogle

    Write-Section -Text "Update & Security"
    Write-Caption -Text "Windows Update"
    Write-Status -Types "-", $TweakType -Status "Disabling Automatic Download and Installation of Windows Updates..."
    If (!(Test-Path "$PathToLMPoliciesWindowsUpdate")) {
        New-Item -Path "$PathToLMPoliciesWindowsUpdate" -Force | Out-Null
    }
    # [@] (2 = Notify before download, 3 = Automatically download and notify of installation)
    # [@] (4 = Automatically download and schedule installation, 5 = Automatic Updates is required and users can configure it)
    Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "AUOptions" -Type DWord -Value 2

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Automatic Updates..."
    # [@] (0 = Enable Automatic Updates, 1 = Disable Automatic Updates)
    Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "NoAutoUpdate" -Type DWord -Value $Zero

    Write-Status -Types "+", $TweakType -Status "Setting Scheduled Day to Every day..."
    # [@] (0 = Every day, 1~7 = The days of the week from Sunday (1) to Saturday (7) (Only valid if AUOptions = 4))
    Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "ScheduledInstallDay" -Type DWord -Value 0

    Write-Status -Types "-", $TweakType -Status "Setting Scheduled time to 03h00m..."
    # [@] (0-23 = The time of day in 24-hour format)
    Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "ScheduledInstallTime" -Type DWord -Value 3

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Automatic Reboot after update..."
    # [@] (0 = Enable Automatic Reboot after update, 1 = Disable Automatic Reboot after update)
    Set-ItemProperty -Path "$PathToLMPoliciesWindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Change Windows Updates to 'Notify to schedule restart'..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Restricting Windows Update P2P downloads for Local Network only..."
    If (!(Test-Path "$PathToLMDeliveryOptimizationCfg")) {
        New-Item -Path "$PathToLMDeliveryOptimizationCfg" -Force | Out-Null
    }
    # [@] (0 = Off, 1 = Local Network only, 2 = Local Network private peering only)
    # [@] (3 = Local Network and Internet,  99 = Simply Download mode, 100 = Bypass mode)
    Set-ItemProperty -Path "$PathToLMDeliveryOptimizationCfg" -Name "DODownloadMode" -Type DWord -Value $One

    Write-Caption -Text "Troubleshooting"
    Write-Status -Types "+", $TweakType -Status "Enabling Automatic Recommended Troubleshooting, then notify me..."
    If (!(Test-Path "$PathToLMWindowsTroubleshoot")) {
        New-Item -Path "$PathToLMWindowsTroubleshoot" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMWindowsTroubleshoot" -Name "UserPreference" -Type DWord -Value 3

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows Spotlight Features..."
    If (!(Test-Path "$PathToCUPoliciesCloudContent")) {
        New-Item -Path "$PathToCUPoliciesCloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "ConfigureWindowsSpotlight" -Type DWord -Value 2
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "IncludeEnterpriseSpotlight" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnSettings" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Tailored Experiences..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Third Party Suggestions..."
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableThirdPartySuggestions" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value $One

    # Reference: https://forums.guru3d.com/threads/windows-10-registry-tweak-for-disabling-drivers-auto-update-controversy.418033/
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) automatic driver updates..."
    # [@] (0 = Yes, do this automatically, 1 = No, let me choose what to do, Always install the best, 2 = [...] Install driver software from Windows Update, 3 = [...] Never install driver software from Windows Update
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value $One
    # [@] (0 = Enhanced icons enabled, 1 = Enhanced icons disabled)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value $One

    If (!(Test-Path "$PathToLMPoliciesSQMClient")) {
        New-Item -Path "$PathToLMPoliciesSQMClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesSQMClient" -Name "CEIPEnable" -Type DWord -Value $Zero
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value $Zero
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value $One

    # Details: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-2004#windows-system-startup-event-traces-autologgers
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) some startup event traces (AutoLoggers)..."
    If (!(Test-Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener")) {
        New-Item -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToLMAutoLogger\SQMLogger" -Name "Start" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: HotSpot Sharing'..."
    If (!(Test-Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Name "value" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: Shared HotSpot Auto-Connect'..."
    If (!(Test-Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots")) {
        New-Item -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type DWord -Value $Zero
}
}

else {
    Write-Output "Windows will keep looking into your PC for no reason."
}

Write-Caption "Deleting useless registry keys... if you see red lines it's because they already do not exist :)"
$KeysToDelete = @(
    # Remove Background Tasks
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
    # Microsoft Edge keys
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
    "HKLM:\Software\Wow6432Node\Clients\StartMenuInternet\Microsoft Edge"
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"
    # Windows File
    "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    # Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
    # Scheduled Tasks to delete
    "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
    # Windows Protocol Keys
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
    # Windows Share Target
    "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
)
ForEach ($Key in $KeysToDelete) {
    If ((Test-Path $Key)) {
        Write-Status -Types "-", $TweakType -Status "Removing Key: [$Key]"
        Remove-Item $Key -Recurse
    } Else {
        Write-Status -Types "?", $TweakType -Status "The registry key $Key does not exist"
    }
}

Write-Output "Do you want to optimize security? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y"){
    # Thanks to Win-Debloat-Tools: https://github.com/LeDragoX/Win-Debloat-Tools/blob/main/src/scripts/Optimize-Security.ps1
Import-Module -DisableNameChecking "$PSScriptRoot\lib\Get-HardwareInfo.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\lib\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\lib\Individual-Tweaks.psm1"

# Adapted from: https://youtu.be/xz3oXHleKoM
# Adapted from: https://github.com/ChrisTitusTech/win10script
# Adapted from: https://github.com/kalaspuffar/windows-debloat

function Optimize-Security() {
    $TweakType = "Security"
    # Initialize all Path variables used to Registry Tweaks
    $PathToLMPoliciesEdge = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
    $PathToLMPoliciesMRT = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
    $PathToCUExplorer = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

    Write-Title "Security Tweaks"

    Write-Section "Windows Firewall"
    Write-Status -Types "+", $TweakType -Status "Enabling default firewall profiles..."
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

    Write-Section "Windows Defender"
    Write-Status -Types "?", $TweakType -Status "If you already use another antivirus, nothing will happen." -Warning
    Write-Status -Types "+", $TweakType -Status "Ensuring your Windows Defender is ENABLED..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWORD -Value 0
    Set-MpPreference -DisableRealtimeMonitoring $false -Force

    Write-Status -Types "+", $TweakType -Status "Enabling Microsoft Defender Exploit Guard network protection..."
    Set-MpPreference -EnableNetworkProtection Enabled -Force

    Write-Status -Types "+", $TweakType -Status "Enabling detection for potentially unwanted applications and block them..."
    Set-MpPreference -PUAProtection Enabled -Force

    Write-Section "SmartScreen"
    Write-Status -Types "+", $TweakType -Status "Enabling 'SmartScreen' for Microsoft Edge..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1

    Write-Status -Types "+", $TweakType -Status "Enabling 'SmartScreen' for Store Apps..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 1

    Write-Section "Old SMB Protocol"
    # Details: https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858
    Write-Status -Types "+", $TweakType -Status "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    Write-Section "Autoplay and Autorun (Removable Devices)"
    Write-Status -Types "-", $TweakType -Status "Disabling Autoplay..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

    Write-Status -Types "-", $TweakType -Status "Disabling Autorun for all Drives..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

    Write-Section "Microsoft Store"
    Disable-SearchAppForUnknownExt

    Write-Section "Windows Explorer"
    Write-Status -Types "+", $TweakType -Status "Enabling Show file extensions in Explorer..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "HideFileExt" -Type DWord -Value 0

    Write-Section "User Account Control (UAC)"
    # Details: https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings
    Write-Status -Types "+", $TweakType -Status "Raising UAC level..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

    Write-Section "Windows Update"
    # Details: https://forums.malwarebytes.com/topic/246740-new-potentially-unwanted-modification-disablemrt/
    Write-Status -Types "+", $TweakType -Status "Enabling offer Malicious Software Removal Tool via Windows Update..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesMRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 0
}
} else {
    Write-Output "Security will not be optimized."
}

Write-Output "Do you want to disable and stop useless services? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output "The useless services will be removed."
    function Stop-UnnecessaryServices
	{
		$servicesAuto = @"
			"AudioSrv",
			"AudioEndpointBuilder",
			"BFE",
			"BrokerInfrastructure",
			"CDPSvc",
			"CDPUserSvc_dc2a4",
			"CoreMessagingRegistrar",
			"CryptSvc",
			"DPS",
			"DcomLaunch",
			"Dhcp",
			"DispBrokerDesktopSvc",
			"Dnscache",
			"DoSvc",
			"DusmSvc",
			"EventLog",
			"EventSystem",
			"FontCache",
			"LSM",
			"LanmanServer",
			"LanmanWorkstation",
			"MapsBroker",
			"MpsSvc",
			"OneSyncSvc_dc2a4",
			"Power",
			"ProfSvc",
			"RpcEptMapper",
			"RpcSs",
			"SCardSvr",
			"SENS",
			"SamSs",
			"Schedule",
			"SgrmBroker",
			"ShellHWDetection",
			"Spooler",
			"SystemEventsBroker",
			"TextInputManagementService",
			"Themes",
			"TrkWks",
			"UserManager",
			"VGAuthService",
			"VMTools",
			"WSearch",
			"Wcmsvc",
			"WinDefend",
			"Winmgmt",
			"WlanSvc",
			"WpnService",
			"WpnUserService_dc2a4",
			"cbdhsvc_dc2a4",
			"gpsvc",
			"iphlpsvc",
			"mpssvc",
			"nsi",
			"sppsvc",
			"tiledatamodelsvc",
			"vm3dservice",
			"webthreatdefusersvc_dc2a4",
			"wscsvc"
"@		
	
		$allServices = Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $servicesAuto -NotContains $_.Name}
		foreach($service in $allServices)
		{
			Stop-Service -Name $service.Name -PassThru
			Set-Service $service.Name -StartupType Manual
			"Stopping service $($service.Name)" | Out-File -FilePath c:\windows\LogFirstRun.txt -Append -NoClobber
		}
	}

Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Get-HardwareInfo.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Set-Service-Startup.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Title-Templates.psm1"

# Adapted from: https://youtu.be/qWESrvP_uU8
# Adapted from: https://github.com/ChrisTitusTech/win10script
# Adapted from: https://gist.github.com/matthewjberger/2f4295887d6cb5738fa34e597f457b7f
# Adapted from: https://github.com/Sycnex/Windows10Debloater

function Optimize-ServicesRunning() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    $IsSystemDriveSSD = $(Get-OSDriveType) -eq "SSD"
    $EnableServicesOnSSD = @("SysMain")

    # Services which will be totally disabled
    $ServicesToDisabled = @(
        "DiagTrack"                                 # DEFAULT: Automatic | Connected User Experiences and Telemetry
        "diagnosticshub.standardcollector.service"  # DEFAULT: Manual    | Microsoft (R) Diagnostics Hub Standard Collector Service
        "dmwappushservice"                          # DEFAULT: Manual    | Device Management Wireless Application Protocol (WAP)
        "GraphicsPerfSvc"                           # DEFAULT: Manual    | Graphics performance monitor service
        "HomeGroupListener"                         # NOT FOUND (Win 10+)| HomeGroup Listener
        "HomeGroupProvider"                         # NOT FOUND (Win 10+)| HomeGroup Provider
        "lfsvc"                                     # DEFAULT: Manual    | Geolocation Service
        "MapsBroker"                                # DEFAULT: Automatic | Downloaded Maps Manager
        "PcaSvc"                                    # DEFAULT: Automatic | Program Compatibility Assistant (PCA)
        "RemoteAccess"                              # DEFAULT: Disabled  | Routing and Remote Access
        "RemoteRegistry"                            # DEFAULT: Disabled  | Remote Registry
        "RetailDemo"                                # DEFAULT: Manual    | The Retail Demo Service controls device activity while the device is in retail demo mode.
        "SysMain"                                   # DEFAULT: Automatic | SysMain / Superfetch (100% Disk usage on HDDs)
        "TrkWks"                                    # DEFAULT: Automatic | Distributed Link Tracking Client
        "WSearch"                                   # DEFAULT: Automatic | Windows Search (100% Disk usage on HDDs, dangerous on SSDs too)
        #Taken from MakeWindowsGreatAgain 1.4.0
        "AJRouter"
        "AppVClient"
        "AssignedAccessManagerSvc"
        "cphs"
        "cplspcon"
        "DiagTrack"
        "DialogBlockingService"
        "esifsvc"
        "HfcDisableService"
        "HPAppHelperCap"
        "HPDiagsCap"
        "HPNetworkCap"
        "HPOmenCap"
        "HPSysInfoCap"
        "HpTouchpointAnalyticsService"
        "igccservice"
        "igfxCUIService2.0.0.0"
        "Intel(R) Capability Licensing Service TCP IP Interface"
        "Intel(R) TPM Provisioning Service"
        "IntelAudioService"
        "jhi_service"
        "LMS"
        "MapsBroker"
        "NetTcpPortSharing"
        "NVDisplay.ContainerLocalSystem"            # In case you need NVIDIA Control Panel, enable again
        "RemoteAccess"
        "RemoteRegistry"
        "RstMwService"
        "RtkAudioUniversalService"
        "shpamsvc"
        "tzautoupdate"
        "UevAgentService"
        "WSearch"
        "XTU3SERVICE"
        # - Services which cannot be disabled (and shouldn't)
        #"wscsvc"                                   # DEFAULT: Automatic | Windows Security Center Service
        #"WdNisSvc"                                 # DEFAULT: Manual    | Windows Defender Network Inspection Service
    )

    # Making the services to run only when needed as 'Manual' | Remove the # to set to Manual
    $ServicesToManual = @(
        "BITS"                           # DEFAULT: Manual    | Background Intelligent Transfer Service
        "edgeupdate"                     # DEFAULT: Automatic | Microsoft Edge Update Service
        "edgeupdatem"                    # DEFAULT: Manual    | Microsoft Edge Update Service²
        "FontCache"                      # DEFAULT: Automatic | Windows Font Cache
        "iphlpsvc"                       # DEFAULT: Automatic | IP Helper Service (IPv6 (6to4, ISATAP, Port Proxy and Teredo) and IP-HTTPS)
        "lmhosts"                        # DEFAULT: Manual    | TCP/IP NetBIOS Helper
        "wuauserv"                       # DEFAULT: Automatic | Windows Update
        "UsoSvc"                         # DEFAULT: Automatic | Update Orchestrator Service (Manages the download and installation of Windows updates)
        #"NetTcpPortSharing"             # DEFAULT: Disabled  | Net.Tcp Port Sharing Service
        "PhoneSvc"                       # DEFAULT: Manual    | Phone Service (Manages the telephony state on the device)
        "SCardSvr"                       # DEFAULT: Manual    | Smart Card Service
        "SharedAccess"                   # DEFAULT: Manual    | Internet Connection Sharing (ICS)
        "stisvc"                         # DEFAULT: Automatic | Windows Image Acquisition (WIA) Service
        "WbioSrvc"                       # DEFAULT: Manual    | Windows Biometric Service (required for Fingerprint reader / Facial detection)
        "Wecsvc"                         # DEFAULT: Manual    | Windows Event Collector Service
        "WerSvc"                         # DEFAULT: Manual    | Windows Error Reporting Service
        "wisvc"                          # DEFAULT: Manual    | Windows Insider Program Service
        "WMPNetworkSvc"                  # DEFAULT: Manual    | Windows Media Player Network Sharing Service
        "WpnService"                     # DEFAULT: Automatic | Windows Push Notification Services (WNS)
        #Taken from MakeWindowsGreatAgain 1.4.0
        "Fax"
        "fhsvc"
        # - Diagnostic Services
        "DPS"                            # DEFAULT: Automatic | Diagnostic Policy Service
        "WdiServiceHost"                 # DEFAULT: Manual    | Diagnostic Service Host
        "WdiSystemHost"                  # DEFAULT: Manual    | Diagnostic System Host
        # - Bluetooth services
        "BTAGService"                    # DEFAULT: Manual    | Bluetooth Audio Gateway Service
        "BthAvctpSvc"                    # DEFAULT: Manual    | AVCTP Service
        "bthserv"                        # DEFAULT: Manual    | Bluetooth Support Service
        "RtkBtManServ"                   # DEFAULT: Automatic | Realtek Bluetooth Device Manager Service
        # - Xbox services
        "XblAuthManager"                 # DEFAULT: Manual    | Xbox Live Auth Manager
        "XblGameSave"                    # DEFAULT: Manual    | Xbox Live Game Save
        "XboxGipSvc"                     # DEFAULT: Manual    | Xbox Accessory Management Service
        "XboxNetApiSvc"                  # DEFAULT: Manual    | Xbox Live Networking Service
        # - NVIDIA services
        "NVDisplay.ContainerLocalSystem" # DEFAULT: Automatic | NVIDIA Display Container LS (NVIDIA Control Panel)
        "NvContainerLocalSystem"         # DEFAULT: Automatic | NVIDIA LocalSystem Container (GeForce Experience / NVIDIA Telemetry)
        # - Printer services
        #"PrintNotify"                   # DEFAULT: Manual    | WARNING! REMOVING WILL TURN PRINTING LESS MANAGEABLE | Printer Extensions and Notifications
        #"Spooler"                       # DEFAULT: Automatic | WARNING! REMOVING WILL DISABLE PRINTING              | Print Spooler
        # - Wi-Fi services
        #"WlanSvc"                       # DEFAULT: Manual (No Wi-Fi devices) / Automatic (Wi-Fi devices) | WARNING! REMOVING WILL DISABLE WI-FI, DON'T TELL ME I DIDN'T WARN YOU, LITTLE PP BITCHES | WLAN AutoConfig
        # - 3rd Party Services
        "gupdate"                        # DEFAULT: Automatic | Google Update Service
        "gupdatem"                       # DEFAULT: Manual    | Google Update Service²
        # FROM MAKEWINDOWSGREATAGAIN 1.2.1
        "EventSystem"                    # DEFAULT: Automatic | COM+ Event System
        "DusmSvc"                        # DEFAULT: Automatic | Data Usage
        "DispBrokerDesktopSvc"           # DEFAULT: Automatic | Display Policy Service
        "nsi"                            # DEFAULT: Automatic | Network Store Interface Service
        "ShellHWDetection"               # DEFAULT: Automatic | Shell Hardware Detection
        "SysMain"                        # DEFAULT: Automatic | SysMain
        "SENS"                           # DEFAULT: Automatic | System Event Notification Service
        "EventLog"                       # DEFAULT: Automatic | Windows Event Log
        "LanmanWorkstation"              # DEFAULT: Automatic | Workstation
        "Themes"                         # DEFAULT: Automatic | Themes
        "ProfSvc"                        # DEFAULT: Automatic | User Profile Service
        "SamSs"                          # DEFAULT: Automatic | Security Acoounts Manager
        "CDPSvc"                         # DEFAULT: Automatic (Delayed Start) | Connected Devices Platform Service
        "edgeupdate"                     # DEFAULT: Automatic (Delayed Start) | Microsoft Edge Update Service (edgeupdate)
        "StorSvc"                        # DEFAULT: Automatic (Delayed Start) | Storage Service
        "CryptSvc"                       # DEFAULT: Automatic (Delayed Start) | Cryptographic Services
        "LanmanServer"                   # DEFAULT: Automatic (Delayed Start) | Server
        "Killer Network Service"
    )

    Write-Title -Text "Services tweaks"
    Write-Section -Text "Disabling services from Windows"

    If ($Revert) {
        Write-Status -Types "*", "Service" -Status "Reverting the tweaks is set to '$Revert'."
        $CustomMessage = { "Resetting $Service ($((Get-Service $Service).DisplayName)) as 'Manual' on Startup ..." }
        Set-ServiceStartup -Manual -Services $ServicesToDisabled -Filter $EnableServicesOnSSD -CustomMessage $CustomMessage
    } Else {
        Set-ServiceStartup -Disabled -Services $ServicesToDisabled -Filter $EnableServicesOnSSD
    }

    Write-Section -Text "Enabling services from Windows"

    If ($IsSystemDriveSSD -or $Revert) {
        $CustomMessage = { "The $Service ($((Get-Service $Service).DisplayName)) service works better in 'Automatic' mode on SSDs ..." }
        Set-ServiceStartup -Automatic -Services $EnableServicesOnSSD -CustomMessage $CustomMessage
    }

    Set-ServiceStartup -Manual -Services $ServicesToManual
}

function Main() {
    # List all services:
    #Get-Service | Select-Object StartType, Status, Name, DisplayName, ServiceType | Sort-Object StartType, Status, Name | Out-GridView

    If (!$Revert) {
        Optimize-ServicesRunning # Enable essential Services and Disable bloating Services
    } Else {
        Optimize-ServicesRunning -Revert
    }
}

Main
}
else {
    Write-Output "Useless services will not be disabled."
}

Write-Output "Do you want to disable Cortana? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Host "Disabling Cortana"
    $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
	If (!(Test-Path $Cortana1)) {
		New-Item $Cortana1
	}
	Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
	If (!(Test-Path $Cortana2)) {
		New-Item $Cortana2
	}
	Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
	Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
	If (!(Test-Path $Cortana3)) {
		New-Item $Cortana3
	}
	Set-ItemProperty $Cortana3 HarvestContacts -Value 0
}
else {
    Write-Output "Cortana will not be disabled."
}

Write-Output "Do you want to set Windows Update frequency to security only? (y/n)"
$confirm = Read-Host
if($confirm -eq "y"){
    reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "BranchReadinessLevel" /t REG_DWORD /d "20" /f
    reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "365" /f
    reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferQualityUpdatesPeriodInDays " /t REG_DWORD /d "4" /f
}
else {
    Write-Output "Windows updates will not be set to security only."
}
timeout /t 2