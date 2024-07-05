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
    <span class="hljs-variable">$progressPreference</span> = <span class="hljs-string">'silentlyContinue'</span>
<span class="hljs-variable">$latestWingetMsixBundleUri</span> = $(Invoke-RestMethod https://api.github.com/repos/microsoft/winget-cli/releases/latest).assets.browser_download_url | Where-Object {<span class="hljs-variable">$_</span>.EndsWith(<span class="hljs-string">".msixbundle"</span>)}
<span class="hljs-variable">$latestWingetMsixBundle</span> = <span class="hljs-variable">$latestWingetMsixBundleUri</span>.Split(<span class="hljs-string">"/"</span>)[-1]
Write-Information <span class="hljs-string">"Downloading winget to artifacts directory..."</span>
Invoke-WebRequest -Uri <span class="hljs-variable">$latestWingetMsixBundleUri</span> -OutFile <span class="hljs-string">"./<span class="hljs-variable">$latestWingetMsixBundle</span>"</span>
Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage <span class="hljs-variable">$latestWingetMsixBundle</span>
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