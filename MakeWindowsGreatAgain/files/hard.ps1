$host.ui.RawUI.WindowTitle = 'MakeWindowsGreatAgain 2.0.0 - 2024.06.07 (Hard)'
timeout /t 2
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
            "Microsoft.BingWeather"                  # Weather
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
            "Microsoft.Whiteboard"                   # Microsoft Whiteboard
            "Microsoft.WindowsAlarms"                # Alarms
            "microsoft.windowscommunicationsapps"
            "Microsoft.WindowsMaps"                  # Maps
            "Microsoft.WindowsPhone"
            "Microsoft.WindowsReadingList"
            "Microsoft.WindowsSoundRecorder"         # Windows Sound Recorder
            "Microsoft.XboxApp"                      # Xbox Console Companion
            "Microsoft.YourPhone"                    # Your Phone
            "Microsoft.ZuneVideo"                    # Movies & TV
            "Microsoft.GamingApp"			         # Xbox App
            "MicrosoftCorporationII.MicrosoftFamily" # Parental Control (no kids allowed here)
            "*Microsoft.XboxGamingOverlay*"          # Discord is better
    
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
    
            # Apps which other apps depend on
            "Microsoft.Advertising.Xaml"
    
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
            "Microsoft.WindowsCamera"           # Camera
            "Microsoft.WindowsFeedbackHub"      # Feedback Hub
    
            # [DIY] Common Streaming services
    
            "*Netflix*"                        # Netflix
            "*Spotify*"
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

        # Disables Xbox Game Bar (avoids "you need an app to open this ms-gamingoverlay link")
        reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR /f /t REG_DWORD /v "AppCaptureEnabled" /d 0
        reg add HKEY_CURRENT_USER\System\GameConfigStore /f /t REG_DWORD /v "GameDVR_Enabled" /d 0
        # Thanks to AVeYo: https://www.reddit.com/r/Windows11/comments/vm046d/comment/ie0j6o3/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button
        reg add HKCR\ms-gamebar /f /ve /d URL:ms-gamebar 2>&1 >''
        reg add HKCR\ms-gamebar /f /v "URL Protocol" /d "" 2>&1 >''
        reg add HKCR\ms-gamebar /f /v "NoOpenWith" /d "" 2>&1 >''
        reg add HKCR\ms-gamebar\shell\open\command /f /ve /d "\`"$env:SystemRoot\System32\systray.exe\`"" 2>&1 >''
        reg add HKCR\ms-gamebarservices /f /ve /d URL:ms-gamebarservices 2>&1 >''
        reg add HKCR\ms-gamebarservices /f /v "URL Protocol" /d "" 2>&1 >''
        reg add HKCR\ms-gamebarservices /f /v "NoOpenWith" /d "" 2>&1 >''
        reg add HKCR\ms-gamebarservices\shell\open\command /f /ve /d "\`"$env:SystemRoot\System32\systray.exe\`"" 2>&1 >''
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


#Removes Live Tiles Bloatware
Write-Output "Do you want to reset the Start Menu Layout to eliminate bloatware Live Tiles? (Windows 10 Only) (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output 'You are running Windows 10, the Start Menu layout will be reset'
    timeout /t 2
    $START_MENU_LAYOUT = @"
    <LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
        <LayoutOptions StartTileGroupCellWidth="6" />
        <DefaultLayoutOverride>
            <StartLayoutCollection>
                <defaultlayout:StartLayout GroupCellWidth="6" />
            </StartLayoutCollection>
        </DefaultLayoutOverride>
    </LayoutModificationTemplate>
"@

    $layoutFile="C:\Windows\StartMenuLayout.xml"

    #Delete layout file if it already exists
    If(Test-Path $layoutFile) {
        Remove-Item $layoutFile
    }

    #Creates the blank layout file
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

    $regAliases = @("HKLM", "HKCU")

    #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        IF(!(Test-Path -Path $keyPath)) { 
            New-Item -Path $basePath -Name "Explorer"
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }

    #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Stop-Process -name explorer
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5

    #Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer" 
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
    }

    #Restart Explorer and delete the layout file
    Stop-Process -name explorer

    # Uncomment the next line to make clean start menu default for all new users
    Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

    Remove-Item $layoutFile
}

else {
    Write-Output "Start Menu Layout will not be reset."
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

Write-Output "Do you want to optimize privacy settings? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output 'Windows will never again track you.'
    Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"title-templates.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\utils\"individual-tweaks.psm1"

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
        Write-Status -Types "*", $TweakType -Status "Reverting the tweaks is set to '$Revert'." -Warning
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

    Write-Status -Types "?", $TweakType -Status "From Path: $PathToCUContentDeliveryManager" -Warning
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

Write-Caption "Deleting useless registry keys..."
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
        Write-Status -Types "?", $TweakType -Status "The registry key $Key does not exist" -Warning
    }
}

function Main() {
If (!$Revert) {
    Optimize-Privacy # Disable Registries that causes slowdowns and privacy invasion
} Else {
    Optimize-Privacy -Revert
}
}
Main

Write-Output "Do you want to disable and stop useless services? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    Write-Output "The useless services will be removed."
mkdir C:\MakeWindowsGreatAgain\backup    
# Saves a copy of running services before running this part to be restored if needed
# Get all services and filter by start type
$automaticServices = Get-Service | Where-Object { $_.StartType -eq "Automatic" } | Select-Object -ExpandProperty Name
$manualServices = Get-Service | Where-Object { $_.StartType -eq "Manual" } | Select-Object -ExpandProperty Name
$disabledServices = Get-Service | Where-Object { $_.StartType -eq "Disabled" } | Select-Object -ExpandProperty Name

# Define the file path for the output
$AutoOutput = "C:\MakeWindowsGreatAgain\backup\autoserv.txt"
$ManOutput = "C:\MakeWindowsGreatAgain\backup\manserv.txt"
$DisOutput = "C:\MakeWindowsGreatAgain\backup\disserv.txt"

# Create or overwrite the output file
$automaticServices | Out-File -FilePath $AutoOutput
$manualServices | Out-File -FilePath $ManOutput
$disabledServices | Out-File -FilePath $DisOutput
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
        
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"get-hardware-info.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"set-service-startup.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"title-templates.psm1"

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

    $IsSystemWindows11 = $(Get-ComputerInfo | Select-Object -expand OsName) -match 11
    $EnableServicesOnWindows11 = @("EventLog")

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
        "AJRouter"
        "AppVClient"
        "AssignedAccessManagerSvc"
        "cphs"
        "cplspcon"
        "DiagTrack"
        "DialogBlockingService"
        "esifsvc"
        "ETDService"                                # In case of problems, enable again.
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
        "Surfshark Service"
        "tzautoupdate"
        "UevAgentService"
        "WSearch"
        "XTU3SERVICE"
        #MSI bloatware - taken from MakeWindowsGreatAgain 1.4.0
        "Micro Star SCM"
        "MSI_Center_Service"
        "MSI Foundation Service"
        "MSI_VoiceControl_Service"
        "Mystic_Light_Service"
        "NahimicService"
        "NortonSecurity"
        "nsWscSvc"
        "FvSvc"
        "RtkAudioUniversalService"
        "LightKeeperService"
        "AASSvc"
        "AcerLightningService"
        "DtsApo4Service"
        "Killer Analytics Service"
        "KNDBWM"
        "KAPSService"
        "McAWFwk"
        "McAPExe"
        "mccspsvc"
        "mfefire"
        "ModuleCoreService"
        "PEFService"
        "mfemms"
        "mfevtp"
        "McpManagementService"
        "TbtP2pShortcutService"
        "AMD Crash Defender Service"
        "AMD External Events Utility"
        "ArmouryCrateControlInterface"
        "ArmouryCrateService"
        "AsusAppService"
        "LightingService"
        "ASUSLinkNear"
        "ASUSLinkRemote"
        "ASUSOptimization"
        "ASUSSoftwareManager"
        "ASUSSwitch"
        "ASUSSystemAnalysis"
        "ASUSSystemDiagnosis"
        "asus"
        "asusm"
        "AsusCertService"
        "FMAPOService"
        "mc-wps-secdashboardservice"
        "Aura Wallpaper Service"
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
                "UserDataSvc_2b9ad"
        "UnistoreSvc_2b9ad"
        "UdkUserSvc_2b9ad"
        "PrintWorkflowUserSvc_2b9ad"
        "PimIndexMaintenanceSvc_2b9ad"
        "DevicesFlowUserSvc_2b9ad"
        "DevicePickerUserSvc_2b9ad"
        "DeviceAssociationBrokerSvc_2b9ad"
        "CredentialEnrollmentManagerUserSvc_2b9ad"
        "ConsentUxUserSvc_2b9ad"
        "cbdhsvc_2b9ad"
        "CaptureService_2b9ad"
        "BcastDVRUserService_2b9ad"
        "AarSvc_2b9ad"
        "XboxNetApiSvc"
        "XblAuthManager"
        "WwanSvc"
        "WpnService"
        "WpcMonSvc"
        "workfolderssvc"
        "WMPNetworkSvc"
        "wmiApSrv"
        "WManSvc"
        "WinRM"
        "WinHttpAutoProxySvc"
        "WiaRpc"
        "wercplsupport"
        "Wecsvc"
        "WdNisSvc"
        "WdiSystemHost"
        "WdiServiceHost"
        "wcncsvc"
        "wbengine"
        "WalletService"
        "WaaSMedicSvc"
        "VSS"
        "vds"
        "VacSvc"
        "UsoSvc"
        "upnphost"
        "UmRdpService"
        "TrustedInstaller"
        "TroubleshootingSvc"
        "TokenBroker"
        "TieringEngineService"
        "TapiSrv"
        "swprv"
        "Surfshark WireGuard"
        "StateRepository"
        "SstpSvc"
        "SSDPSRV"
        "SNMPTRAP"
        "smphost"
        "SharedRealitySvc"
        "SessionEnv"
        "Sense"
        "SecurityHealthService"
        "seclogon"
        "SDRSVC"
        "SCPolicySvc"
        "RtkBtManServ"
        "RpcLocator"
        "RmSvc"
        "RetailDemo"
        "RasAuto"
        "QWAVE"
        "PrintNotify"
        "PNRPsvc"
        "PNRPAutoReg"
        "PlugPlay"
        "pla"
        "PerfHost"
        "perceptionsimulation"
        "PeerDistSvc"
        "PcaSvc"
        "p2psvc"
        "p2pimsvc"
        "NVDisplay.ContainerLocalSystem"
        "NlaSvc"
        "netprofm"
        "Netman"
        "MsKeyboardFilter"
        "msiserver"
        "MSiSCSI"
        "MSDTC"
        "MozillaMaintenance"
        "LxpSvc"
        "lltdsvc"
        "InstallService"
        "fdPHost"
        "Fax"
        "EventLog"
        "EntAppSvc"
        "Eaphost"
        "DPS"
        "dot3svc"
        "DmEnrollmentSvc"
        "diagnosticshub.standardcollector.service"
        "defragsvc"
        "COMSysApp"
        "BITS"
        "AxInstSV"
        "AppReadiness"
        "AppMgmt"
        "ALG"
        "MessagingService_2b9ad"
        "BluetoothUserService_2b9ad"
        "XboxGipSvc"
        "XblGameSave"
        "wuauserv"
        "WPDBusEnum"
        "wlpasvc"
        "wlidsvc"
        "wisvc"
        "WFDSConMgrSvc"
        "WerSvc"
        "WEPHOSTSVC"
        "WebClient"
        "WbioSrvc"
        "WarpJITSvc"
        "W32Time"
        "vmicvss"
        "vmicvmsession"
        "vmictimesync"
        "vmicshutdown"
        "vmicrdv"
        "vmickvpexchange"
        "vmicheartbeat"
        "vmicguestinterface"
        "TimeBrokerSvc"
        "TabletInputService"
        "svsvc"
        "StorSvc"
        "spectrum"
        "SmsRouter"
        "SharedAccess"
        "SensrSvc"
        "SensorService"
        "SensorDataService"
        "SEMgrSvc"
        "ScDeviceEnum"
        "SCardSvr"
        "PushToInstall"
        "PolicyAgent"
        "PhoneSvc"
        "NgcSvc"
        "NgcCtnrSvc"
        "NetSetupSvc"
        "NcdAutoSetup"
        "NcbService"
        "NcaSvc"
        "NaturalAuthentication"
        "lmhosts"
        "LicenseManager"
        "lfsvc"
        "KtmRm"
        "IpxlatCfgSvc"
        "IKEEXT"
        "icssvc"
        "HvHost"
        "hidserv"
        "GraphicsPerfSvc"
        "FrameServer"
        "fhsvc"
        "FDResPub"
        "embeddedmode"
        "EFS"
        "edgeupdatem"
        "edgeupdate"
        "DsSvc"
        "DsmSvc"
        "dmwappushservice"
        "diagsvc"
        "DevQueryBroker"
        "DeviceInstall"
        "DeviceAssociationService"
        "CscService"
        "ClipSVC"
        "CertPropSvc"
        "CDPSvc"
        "bthserv"
        "BthAvctpSvc"
        "BTAGService"
        "autotimesvc"
        "AppXSvc"
        "Appinfo"
        "AppIDSvc"
    )

    Write-Title -Text "Services tweaks"
    Write-Section -Text "Disabling services from Windows"

    Set-ServiceStartup -Manual -Services $ServicesToManual
    If ($Revert) {
        Write-Status -Types "*", "Service" -Status "Reverting the tweaks is set to '$Revert'." -Warning
        $CustomMessage = { "Resetting $Service ($((Get-Service $Service).DisplayName)) as 'Manual' on Startup ..." }
        Set-ServiceStartup -Manual -Services $ServicesToDisabled -Filter $EnableServicesOnSSD $EnableServicesOnWindows11 -CustomMessage $CustomMessage
    } Else {
        Set-ServiceStartup -Disabled -Services $ServicesToDisabled -Filter $EnableServicesOnSSD
    }

    Write-Section -Text "Enabling services from Windows"

     If ($IsSystemDriveSSD -or $Revert) {
        $CustomMessage = { "The $Service ($((Get-Service $Service).DisplayName)) service works better in 'Automatic' mode on SSDs ..." }
        Set-ServiceStartup -Automatic -Services $EnableServicesOnSSD -CustomMessage $CustomMessage
    }

    If ($IsSystemWindows11 -or $Revert) {
        $CustomMessage = { "The $Service ($((Get-Service $Service).DisplayName)) service works better in 'Automatic' mode on Windows 11 ..." }
        Set-ServiceStartup -Automatic -Services $EnableServicesOnWindows11 -CustomMessage $CustomMessage
    }
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

#Removes Microsoft Store
Write-Output "Do you want to uninstall Microsoft Store?(y/n)"
$confirm = Read-Host

if ($confirm -eq "y") {
    Write-Output "Uninstalling Microsoft Store. AppX sideload and Winget will still be available."
    Get-AppxPackage -Name Microsoft.WindowsStore -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -Name Microsoft.StorePurchaseApp -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -alluser *WindowsStore* | Remove-AppxPackage -ErrorAction SilentlyContinue
} else {
    Write-Output "Microsoft Store will not be uninstalled."
}


#Removes Microsoft Edge
Write-Output "Do you want to uninstall Microsoft Edge?(y/n)"
$confirm = Read-Host

if ($confirm -eq "y") {
    # Script Metadata
# Created by AveYo, source: https://raw.githubusercontent.com/AveYo/fox/main/Edge_Removal.bat
# Powershell Conversion and Refactor done by Chris Titus Tech

# Initial Configuration
$remove_win32 = @("Microsoft Edge", "Microsoft Edge Update")
$remove_appx = @("MicrosoftEdge")
$skip = @() # Optional: @("DevTools")

$also_remove_webview = 0
if ($also_remove_webview -eq 1) {
    $remove_win32 += "Microsoft EdgeWebView"
    $remove_appx += "WebExperience", "Win32WebViewHost"
}

# Administrative Privileges Check

# Get the 'SetPrivilege' method from System.Diagnostics.Process type
$setPrivilegeMethod = [System.Diagnostics.Process].GetMethod('SetPrivilege', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)

# List of privileges to set
$privileges = @(
    'SeSecurityPrivilege',
    'SeTakeOwnershipPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege'
)

# Invoke the method for each privilege
foreach ($privilege in $privileges) {
    $setPrivilegeMethod.Invoke($null, @($privilege, 2))
}

# Edge Removal Procedures

# Define processes to shut down
$processesToShutdown = @(
    'explorer', 'Widgets', 'widgetservice', 'msedgewebview2', 'MicrosoftEdge*', 'chredge',
    'msedge', 'edge', 'msteams', 'msfamily', 'WebViewHost', 'Clipchamp'
)

# Kill explorer process
Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue

# Kill the processes from the list
$processesToShutdown | ForEach-Object {
    Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue
}

# Set path for Edge executable
$MS = ($env:ProgramFiles, ${env:ProgramFiles(x86)})[[Environment]::Is64BitOperatingSystem] + '\Microsoft\Edge\Application\msedge.exe'

# Clean up certain registry entries
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ie_to_edge_stub.exe" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path 'Registry::HKEY_Users\S-1-5-21*\Software\Classes\microsoft-edge' -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path 'Registry::HKEY_Users\S-1-5-21*\Software\Classes\MSEdgeHTM' -Recurse -ErrorAction SilentlyContinue

# Create new registry entries
New-Item -Path "HKLM:\SOFTWARE\Classes\microsoft-edge\shell\open\command" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\microsoft-edge\shell\open\command" -Name '(Default)' -Value "`"$MS`" --single-argument %%1" -Force -ErrorAction SilentlyContinue

New-Item -Path "HKLM:\SOFTWARE\Classes\MSEdgeHTM\shell\open\command" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\MSEdgeHTM\shell\open\command" -Name '(Default)' -Value "`"$MS`" --single-argument %%1" -Force -ErrorAction SilentlyContinue

# Remove certain registry properties
$registryPaths = @('HKLM:\SOFTWARE\Policies', 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')
$edgeProperties = @('InstallDefault', 'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}', 'Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')
foreach ($path in $registryPaths) {
    foreach ($prop in $edgeProperties) {
        Remove-ItemProperty -Path "$path\Microsoft\EdgeUpdate" -Name $prop -Force -ErrorAction SilentlyContinue
    }
}

$edgeupdate = 'Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
$webvupdate = 'Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$on_actions = @('on-os-upgrade', 'on-logon', 'on-logon-autolaunch', 'on-logon-startup-boost')
$registryBases = @('HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\Wow6432Node')
foreach ($base in $registryBases) {
    foreach ($launch in $on_actions) {
        Remove-Item -Path "$base\$edgeupdate\Commands\$launch" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$base\$webvupdate\Commands\$launch" -Force -ErrorAction SilentlyContinue
    }
}

# Clear specific registry keys
$registryPaths = @('HKCU:', 'HKLM:')
$nodes = @('', '\Wow6432Node')
foreach ($regPath in $registryPaths) {
    foreach ($node in $nodes) {
        foreach ($i in $remove_win32) {
            Remove-ItemProperty -Path "$regPath\SOFTWARE${node}\Microsoft\Windows\CurrentVersion\Uninstall\$i" -Name 'NoRemove' -Force -ErrorAction SilentlyContinue
            New-Item -Path "$regPath\SOFTWARE${node}\Microsoft\EdgeUpdateDev" -Force | Out-Null
            Set-ItemProperty -Path "$regPath\SOFTWARE${node}\Microsoft\EdgeUpdateDev" -Name 'AllowUninstall' -Value 1 -Type Dword -Force
        }
    }
}

# Locate setup.exe and ie_to_edge_stub.exe
$foldersToSearch = @('LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles') | ForEach-Object {
    [Environment]::GetFolderPath($_)
}

$edges = @()
$bhoFiles = @()

foreach ($folder in $foldersToSearch) {
    $bhoFiles += Get-ChildItem -Path "$folder\Microsoft\Edge*\ie_to_edge_stub.exe" -Recurse -ErrorAction SilentlyContinue

    $edges += Get-ChildItem -Path "$folder\Microsoft\Edge*\setup.exe" -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.FullName -notlike '*EdgeWebView*' }
}

# Create directory and copy ie_to_edge_stub.exe to it
$destinationDir = "$env:SystemDrive\Scripts"
New-Item -Path $destinationDir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

foreach ($bhoFile in $bhoFiles) {
    if (Test-Path $bhoFile) {
        try {
            Copy-Item -Path $bhoFile -Destination "$destinationDir\ie_to_edge_stub.exe" -Force
        } catch { }
    }
}

## Work on Appx Removals

# Retrieve AppX provisioned packages and all AppX packages
$provisioned = Get-AppxProvisionedPackage -Online
$appxpackage = Get-AppxPackage -AllUsers

# Initialize empty array for EndOfLife packages
$eol = @()

# Define user SIDs and retrieve them from the registry
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18')
if (Test-Path $store) {
    $users += (Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '*S-1-5-21*' }).PSChildName
}

# Process AppX packages for removal
foreach ($choice in $remove_appx) {
    if ([string]::IsNullOrWhiteSpace($choice)) { continue }

    # Process provisioned packages
    $provisioned | Where-Object { $_.PackageName -like "*$choice*" } | ForEach-Object {
        if ($skip -Contains $_.PackageName) { return }

        $PackageName = $_.PackageName
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $_.DisplayName }).PackageFamilyName 

        # Add registry entries
        New-Item -Path "$store\Deprovisioned\$PackageFamilyName" -Force -ErrorAction SilentlyContinue | Out-Null
        $users | ForEach-Object {
            New-Item -Path "$store\EndOfLife\$_\$PackageName" -Force -ErrorAction SilentlyContinue | Out-Null
        }
        $eol += $PackageName

        # Modify non-removable app policy and remove package
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 | Out-Null
        Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers | Out-Null
    }

    # Process all AppX packages
    $appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" } | ForEach-Object {
        if ($skip -Contains $_.PackageFullName) { return }

        $PackageFullName = $_.PackageFullName

        # Add registry entries
        New-Item -Path "$store\Deprovisioned\$_.PackageFamilyName" -Force -ErrorAction SilentlyContinue | Out-Null
        $users | ForEach-Object {
            New-Item -Path "$store\EndOfLife\$_\$PackageFullName" -Force -ErrorAction SilentlyContinue | Out-Null
        }
        $eol += $PackageFullName

        # Modify non-removable app policy and remove package
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 | Out-Null
        Remove-AppxPackage -Package $PackageFullName -AllUsers | Out-Null
    }
}

## Run Edge setup uninstaller

foreach ($setup in $edges) {
    if (Test-Path $setup) {
        $target = if ($setup -like '*EdgeWebView*') { "--msedgewebview" } else { "--msedge" }
        
        $removalArgs = "--uninstall $target --system-level --verbose-logging --force-uninstall"
        
        Write-Host "$setup $removalArgs"
        
        try {
            Start-Process -FilePath $setup -ArgumentList $removalArgs -Wait
        } catch {
            # You may want to add logging or other error handling here.
        }
        
        while ((Get-Process -Name 'setup', 'MicrosoftEdge*' -ErrorAction SilentlyContinue).Path -like '*\Microsoft\Edge*') {
            Start-Sleep -Seconds 3
        }
    }
}

## Cleanup

# Define necessary paths and variables
$edgePaths = $env:ProgramFiles, ${env:ProgramFiles(x86)}
$appDataPath = [Environment]::GetFolderPath('ApplicationData')

# Uninstall Microsoft Edge Update
foreach ($path in $edgePaths) {
    $edgeUpdateExe = "$path\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
    if (Test-Path $edgeUpdateExe) {
        Write-Host $edgeUpdateExe /uninstall
        Start-Process -FilePath $edgeUpdateExe -ArgumentList '/uninstall' -Wait
        while ((Get-Process -Name 'setup','MicrosoftEdge*' -ErrorAction SilentlyContinue).Path -like '*\Microsoft\Edge*') {
            Start-Sleep -Seconds 3
        }
        if ($also_remove_webview -eq 1) {
            foreach ($regPath in 'HKCU:', 'HKLM:') {
                foreach ($node in '', '\Wow6432Node') {
                    Remove-Item -Path "$regPath\SOFTWARE$node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update" -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            Remove-Item -Path "$path\Microsoft\EdgeUpdate" -Recurse -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'MicrosoftEdgeUpdate*' -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

# Remove Edge shortcuts
Remove-Item -Path "$appDataPath\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$appDataPath\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue

# Revert settings related to Microsoft Edge
foreach ($sid in $users) {
    foreach ($packageName in $eol) {
        Remove-Item -Path "$store\EndOfLife\$sid\$packageName" -Force -ErrorAction SilentlyContinue
    }
}

# Set policies to prevent unsolicited reinstalls of Microsoft Edge
$registryPaths = @('HKLM:\SOFTWARE\Policies', 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')
$edgeUpdatePolicies = @{
    'InstallDefault'                     = 0;
    'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' = 0;
    'Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' = 1;
    'DoNotUpdateToEdgeWithChromium'      = 1;
}

foreach ($path in $registryPaths) {
    New-Item -Path "$path\Microsoft\EdgeUpdate" -Force -ErrorAction SilentlyContinue | Out-Null
    foreach ($policy in $edgeUpdatePolicies.GetEnumerator()) {
        Set-ItemProperty -Path "$path\Microsoft\EdgeUpdate" -Name $policy.Key -Value $policy.Value -Type Dword -Force
    }
}

$edgeUpdateActions = @('on-os-upgrade', 'on-logon', 'on-logon-autolaunch', 'on-logon-startup-boost')
$edgeUpdateClients = @(
    'Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}',
    'Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
)
foreach ($client in $edgeUpdateClients) {
    foreach ($action in $edgeUpdateActions) {
        foreach ($regBase in 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\Wow6432Node') {
            $regPath = "$regBase\$client\Commands\$action"
            New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $regPath -Name 'CommandLine' -Value 'systray.exe' -Force
        }
    }
}

## Redirect Edge Shortcuts

# Define Microsoft Edge Paths
$MSEP = ($env:ProgramFiles, ${env:ProgramFiles(x86)})[[Environment]::Is64BitOperatingSystem] + '\Microsoft\Edge\Application'
$IFEO = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$MIN = ('--headless', '--width 1 --height 1')[([environment]::OSVersion.Version.Build) -gt 25179]
$CMD = "$env:systemroot\system32\conhost.exe $MIN"
$DIR = "$env:SystemDrive\Scripts"

# Setup Microsoft Edge Registry Entries
New-Item -Path "HKLM:\SOFTWARE\Classes\microsoft-edge\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\microsoft-edge" -Name '(Default)' -Value 'URL:microsoft-edge' -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\microsoft-edge" -Name 'URL Protocol' -Value '' -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\microsoft-edge" -Name 'NoOpenWith' -Value '' -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\microsoft-edge\shell\open\command" -Name '(Default)' -Value "`"$DIR\ie_to_edge_stub.exe`" %1" -Force

# Setup MSEdgeHTM Registry Entries
New-Item -Path "HKLM:\SOFTWARE\Classes\MSEdgeHTM\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\MSEdgeHTM" -Name 'NoOpenWith' -Value '' -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\MSEdgeHTM\shell\open\command" -Name '(Default)' -Value "`"$DIR\ie_to_edge_stub.exe`" %1" -Force

# Setup Image File Execution Options for Edge and Edge WebView
$exeSettings = @(
    @{ ExeName = 'ie_to_edge_stub.exe'; Debugger = "$CMD $DIR\OpenWebSearch.cmd"; FilterPath = "$DIR\ie_to_edge_stub.exe" },
    @{ ExeName = 'msedge.exe'; Debugger = "$CMD $DIR\OpenWebSearch.cmd"; FilterPath = "$MSEP\msedge.exe" }
)

foreach ($setting in $exeSettings) {
    New-Item -Path "$IFEO\$($setting.ExeName)\0" -Force | Out-Null
    Set-ItemProperty -Path "$IFEO\$($setting.ExeName)" -Name 'UseFilter' -Value 1 -Type Dword -Force
    Set-ItemProperty -Path "$IFEO\$($setting.ExeName)\0" -Name 'FilterFullPath' -Value $setting.FilterPath -Force
    Set-ItemProperty -Path "$IFEO\$($setting.ExeName)\0" -Name 'Debugger' -Value $setting.Debugger -Force
}

# Write OpenWebSearch Batch Script
$OpenWebSearch = @'
@echo off
@title OpenWebSearch Redux

:: Minimize prompt
for /f %%E in ('"prompt $E$S & for %%e in (1) do rem"') do echo;%%E[2t >nul 2>&1

:: Get default browser from registry
call :get_registry_value "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" ProgID DefaultBrowser
if not defined DefaultBrowser (
    echo Error: Failed to get default browser from registry.
    pause
    exit /b
)
if /i "%DefaultBrowser%" equ "MSEdgeHTM" (
    echo Error: Default browser is set to Edge! Change it or remove OpenWebSearch script.
    pause
    exit /b
)

:: Get browser command line
call :get_registry_value "HKCR\%DefaultBrowser%\shell\open\command" "" BrowserCommand
if not defined BrowserCommand (
    echo Error: Failed to get browser command from registry.
    pause
    exit /b
)
set Browser=& for %%i in (%BrowserCommand%) do if not defined Browser set "Browser=%%~i"

:: Set fallback for Edge
call :get_registry_value "HKCR\MSEdgeMHT\shell\open\command" "" FallBack
set EdgeCommand=& for %%i in (%FallBack%) do if not defined EdgeCommand set "EdgeCommand=%%~i"

:: Parse command line arguments and check for redirect or noop conditions
set "URI=" & set "URL=" & set "NOOP=" & set "PassThrough=%EdgeCommand:msedge=edge%"
set "CommandLineArgs=%CMDCMDLINE:"=``% "
call :parse_arguments

if defined NOOP (
    if not exist "%PassThrough%" (
        echo Error: PassThrough path doesn't exist.
        pause
        exit /b
    )
    start "" "%PassThrough%" %ParsedArgs%
    exit /b
)

:: Decode URL
call :decode_url
if not defined URL (
    echo Error: Failed to decode URL.
    pause
    exit /b
)

:: Open URL in default browser
start "" "%Browser%" "%URL%"
exit

:: Functions

:get_registry_value
setlocal
    set regQuery=reg query "%~1" /v %2 /z /se "," /f /e
    if "%~2" equ "" set regQuery=reg query "%~1" /ve /z /se "," /f /e
    for /f "skip=2 tokens=* delims=" %%V in ('%regQuery% 2^>nul') do set "result=%%V"
    if defined result (set "result=%result:*)    =%") else (set "%~3=")
    endlocal & set "%~3=%result%"
exit /b

:decode_url
    :: Brute URL percent decoding
    setlocal enabledelayedexpansion
    set "decoded=%URL:!=}%"
    call :brute_decode
    endlocal & set "URL=%decoded%"
exit /b

:parse_arguments
    :: Remove specific substrings from arguments
    set "CommandLineArgs=%CommandLineArgs:*ie_to_edge_stub.exe`` =%"
    set "CommandLineArgs=%CommandLineArgs:*ie_to_edge_stub.exe =%"
    set "CommandLineArgs=%CommandLineArgs:*msedge.exe`` =%"
    set "CommandLineArgs=%CommandLineArgs:*msedge.exe =%"

    :: Remove any trailing spaces
    if "%CommandLineArgs:~-1%"==" " set "CommandLineArgs=%CommandLineArgs:~0,-1%"

    :: Check if arguments are a redirect or URL
    set "RedirectArg=%CommandLineArgs:microsoft-edge=%"
    set "UrlArg=%CommandLineArgs:http=%"
    set "ParsedArgs=%CommandLineArgs:``="%"

    :: Set NOOP flag if no changes to arguments
    if "%CommandLineArgs%" equ "%RedirectArg%" (set NOOP=1) else if "%CommandLineArgs%" equ "%UrlArg%" (set NOOP=1)

    :: Extract URL if present
    if not defined NOOP (
        set "URL=%CommandLineArgs:*microsoft-edge=%"
        set "URL=http%URL:*http=%"
        if "%URL:~-2%"=="``" set "URL=%URL:~0,-2%"
    )
exit /b


:brute_decode
    :: Brute force URL percent decoding

    set "decoded=%decoded:%%20= %"
    set "decoded=%decoded:%%21=!!"
    set "decoded=%decoded:%%22="%""
    set "decoded=%decoded:%%23=#%"
    set "decoded=%decoded:%%24=$%"
    set "decoded=%decoded:%%25=%%%"
    set "decoded=%decoded:%%26=&%"
    set "decoded=%decoded:%%27='%"
    set "decoded=%decoded:%%28=(%"
    set "decoded=%decoded:%%29=)%" 
    set "decoded=%decoded:%%2A=*%"
    set "decoded=%decoded:%%2B=+%"
    set "decoded=%decoded:%%2C=,%"
    set "decoded=%decoded:%%2D=-%"
    set "decoded=%decoded:%%2E=.%"
    set "decoded=%decoded:%%2F=/%"
    :: ... Continue for other encodings ...

    :: Correct any double percentage signs
    set "decoded=%decoded:%%%%=%"

exit /b



'@
[io.file]::WriteAllText("$DIR\OpenWebSearch.cmd", $OpenWebSearch)


# Final Steps 

# Retrieve the Edge_Removal property from the specified registry paths
$userRegPaths = Get-ChildItem -Path 'Registry::HKEY_Users\S-1-5-21*\Volatile*' -ErrorAction SilentlyContinue
$edgeRemovalPath = $userRegPaths | Get-ItemProperty -Name 'Edge_Removal' -ErrorAction SilentlyContinue

# If the Edge_Removal property exists, remove it
if ($edgeRemovalPath) {
    Remove-ItemProperty -Path $edgeRemovalPath.PSPath -Name 'Edge_Removal' -Force -ErrorAction SilentlyContinue
}

# Ensure the explorer process is running
if (-not (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) {
    Start-Process 'explorer'
}
    
} else {
    Write-Output "Microsoft Edge will not be uninstalled."
}





Write-Output "Do you want to optimize Task Scheduler tasks? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    #Optimizes Task Scheduler tasks
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"set-scheduled-task-state.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"title-templates.psm1"

# Adapted from: https://youtu.be/qWESrvP_uU8
# Adapted from: https://github.com/ChrisTitusTech/win10script
# Adapted from: https://gist.github.com/matthewjberger/2f4295887d6cb5738fa34e597f457b7f
# Adapted from: https://github.com/Sycnex/Windows10Debloater
# Adapted from: https://github.com/kalaspuffar/windows-debloat

function Optimize-TaskScheduler() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    # Adapted from: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations#task-scheduler
    $DisableScheduledTasks = @(
        "\Microsoft\Office\OfficeTelemetryAgentLogOn"
        "\Microsoft\Office\OfficeTelemetryAgentFallBack"
        "\Microsoft\Office\Office 15 Subscription Heartbeat"
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        "\Microsoft\Windows\Application Experience\StartupAppTask"
        "\Microsoft\Windows\Autochk\Proxy"
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"         # Recommended state for VDI use
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"       # Recommended state for VDI use
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"              # Recommended state for VDI use
        "\Microsoft\Windows\Defrag\ScheduledDefrag"                                       # Recommended state for VDI use
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        "\Microsoft\Windows\Location\Notifications"                                       # Recommended state for VDI use
        "\Microsoft\Windows\Location\WindowsActionDialog"                                 # Recommended state for VDI use
        "\Microsoft\Windows\Maps\MapsToastTask"                                           # Recommended state for VDI use
        "\Microsoft\Windows\Maps\MapsUpdateTask"                                          # Recommended state for VDI use
        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"                # Recommended state for VDI use
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"                   # Recommended state for VDI use
        "\Microsoft\Windows\Retail Demo\CleanupOfflineContent"                            # Recommended state for VDI use
        "\Microsoft\Windows\Shell\FamilySafetyMonitor"                                    # Recommended state for VDI use
        "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"                                # Recommended state for VDI use
        "\Microsoft\Windows\Shell\FamilySafetyUpload"
        "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"                          # Recommended state for VDI use
    )

    Write-Title -Text "Task Scheduler tweaks"
    Write-Section -Text "Disabling Scheduled Tasks from Windows"

    If ($Revert) {
        Write-Status -Types "*", "TaskScheduler" -Status "Reverting the tweaks is set to '$Revert'." -Warning
        $CustomMessage = { "Resetting the $ScheduledTask task as 'Ready' ..." }
        Set-ScheduledTaskState -Ready -ScheduledTask $DisableScheduledTasks -CustomMessage $CustomMessage
    } Else {
        Set-ScheduledTaskState -Disabled -ScheduledTask $DisableScheduledTasks
    }
}

function Main() {
    # List all Scheduled Tasks:
    #Get-ScheduledTask | Select-Object -Property State, TaskPath, TaskName, Description | Sort-Object State, TaskPath, TaskName | Out-GridView

    If (!$Revert) {
        Optimize-TaskScheduler # Disable Scheduled Tasks that causes slowdowns
    } Else {
        Optimize-TaskScheduler -Revert
    }
}

Main
}
else {
    Write-Output "Task Scheduler tasks will not be optimized."
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

Write-Output "Do you want to optimize network connectivity? (y/n)"
$confirm = Read-Host
if($confirm -eq "y"){
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting Network AutoTuning to Disabled"
    netsh int tcp set global autotuninglevel=disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Explicit Congestion Notification"
    netsh int tcp set global ecncapability=disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Enabling Direct Cache Access"
    netsh int tcp set global dca=enabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Enabling Network Direct Memory Access"
    netsh int tcp set global netdma=enabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Recieve Side Coalescing"
    netsh int tcp set global rsc=disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Enabling Recieve Side Scaling"
    netsh int tcp set global rss=enabled
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "1" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling TCP Timestamps"
    netsh int tcp set global timestamps=disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting Initial Retransmission Timer"
    netsh int tcp set global initialRto=2000
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting MTU Size"
    netsh interface ipv4 set subinterface “Ethernet” mtu=1500 store=persistent
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Non Sack RTT Resiliency"
    netsh int tcp set global nonsackrttresiliency=disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting Max Syn Retransmissions"
    netsh int tcp set global maxsynretransmissions=2
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Memory Pressure Protection"
    netsh int tcp set security mpp=disabled
    timeout /t 1 /nobreak > NUL
    
    Write-Output "Disabling Windows Scaling Heuristics"
    netsh int tcp set heuristics disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Increasing ARP Cache Size"
    netsh int ip set global neighborcachelimit=4096
    timeout /t 1 /nobreak > NUL

    Write-Output "Enabling CTCP"
    netsh int tcp set supplemental Internet congestionprovider=ctcp
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Task Offloading"
    netsh int ip set global taskoffload=disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling ISATAP"
    netsh int isatap set state disabled
    timeout /t 1 /nobreak > NUL

    Write-Output "Configuring Time to Live"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Enabling TCP Window Scaling"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting TcpMaxDupAcks to 2"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling TCP Selective ACKs"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Increasing Maximum Port Number"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Decreasing Timed Wait Delay"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting Network Priorities"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Configuring Sock Address Size"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Nagle's Algorithm"
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Delivery Optimization"
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Auto Disconnect"
    reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Limiting SMB Sessions"
    reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Oplocks"
    reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Setting IRP Stack Size"
    reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f
    timeout /t 1 /nobreak > NUL
cmd -c "for /f "$($key.Trim())" in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do {
    Write-Output "Disabling NIC Power Savings"
    reg add ""$($key.Trim())"" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "AdvancedEEE" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f
    reg add ""$($key.Trim())"" /v "*EEE" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EEE" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnablePME" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "GigaLite" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f
    reg add ""$($key.Trim())"" /v "PowerDownPll" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "PowerSavingMode" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "SmartPowerDownEnable" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "ULPMode" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "WakeOnLink" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Jumbo Frame"
    reg add ""$($key.Trim())"" /v "JumboPacket" /t REG_SZ /d "1514" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Configuring Buffer Sizes"
    reg add ""$($key.Trim())"" /v "TransmitBuffers" /t REG_SZ /d "4096" /f
    reg add ""$($key.Trim())"" /v "ReceiveBuffers" /t REG_SZ /d "512" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Configuring Offloads"
    reg add ""$($key.Trim())"" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "LsoV1IPv4" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "LsoV2IPv4" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "LsoV2IPv6" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "PMARPOffload" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "PMNSOffload" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f
    timeout /t 1 /nobreak > NUL
    
    Write-Output "Enabling RSS in NIC"
    reg add ""$($key.Trim())"" /v "RSS" /t REG_SZ /d "1" /f
    reg add ""$($key.Trim())"" /v "*NumRssQueues" /t REG_SZ /d "2" /f
    reg add ""$($key.Trim())"" /v "RSSProfile" /t REG_SZ /d "3" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Flow Control"
    reg add ""$($key.Trim())"" /v "*FlowControl" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "FlowControlCap" /t REG_SZ /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Removing Interrupt Delays"
    reg add ""$($key.Trim())"" /v "TxIntDelay" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "RxIntDelay" /t REG_SZ /d "0" /f
    reg add ""$($key.Trim())"" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Removing Adapter Notification Sending"
    reg add ""$($key.Trim())"" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f
    timeout /t 1 /nobreak > NUL

    Write-Output "Disabling Interrupt Moderation"
    reg add ""$($key.Trim())"" /v "*InterruptModeration" /t REG_SZ /d "0" /f
    timeout /t 1 /nobreak > NUL
    
}"
    Write-Output "Enabling WH Send and Recieve"
    Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue
    timeout /t 1 /nobreak > NUL
    
}
else {
    Write-Output "Network connectivity will not be optimized."
}