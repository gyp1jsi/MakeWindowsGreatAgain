$host.ui.RawUI.WindowTitle = 'MakeWindowsGreatAgain 2.0.0 - 2024.07.07(Hard)'
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
        Write-Output -Types "*", $TweakType -Status "Reverting the tweaks is set to '$Revert'."
        $Zero = 1
        $One = 0
        $EnableStatus = @(
            @{ Symbol = "*"; Status = "Re-Enabling"; }
            @{ Symbol = "*"; Status = "Re-Disabling"; }
        )
    }

    # Initialize all Path variables used to Registry Tweaks
    $PathToLMPoliciesAdvertisingInfo = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    $PathToCUContentDeliveryManager = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    $PathToCUDeviceAccessGlobal = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
    $PathToCUInputPersonalization = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $PathToCUInputTIPC = "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
    $PathToCUSiufRules = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"

    Write-Title -Text "Privacy Tweaks"
    If (!$Revert) {
        #Disable-ClipboardHistory
        Disable-Cortana
    } Else {
        #Enable-ClipboardHistory
        Enable-Cortana
    }

    Write-Output "Removing File Explorer Ads (OneDrive, New Features etc.)..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0

    Write-Section -Text "Personalization"
    Write-Caption -Text "Start & Lockscreen"
    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Show me the windows welcome experience after updates..."
    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Get fun facts and tips, etc. on lock screen'..."

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

    Write-Output -Types "?", $TweakType -Status "From Path: $PathToCUContentDeliveryManager"
    ForEach ($Name in $ContentDeliveryManagerDisableOnZero) {
        Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) $($Name): $Zero"
        Set-ItemProperty -Path "$PathToCUContentDeliveryManager" -Name "$Name" -Type DWord -Value $Zero
    }

    Write-Output -Types "-", $TweakType -Status "Disabling 'Suggested Content in the Settings App'..."
    If (Test-Path "$PathToCUContentDeliveryManager\Subscriptions") {
        Remove-Item -Path "$PathToCUContentDeliveryManager\Subscriptions" -Recurse
    }

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Show Suggestions' in Start..."
    If (Test-Path "$PathToCUContentDeliveryManager\SuggestedApps") {
        Remove-Item -Path "$PathToCUContentDeliveryManager\SuggestedApps" -Recurse
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value $One

    Write-Section -Text "Privacy -> Windows Permissions"
    Write-Caption -Text "General"
    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Let apps use my advertising ID..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value $Zero
    If (!(Test-Path "$PathToLMPoliciesAdvertisingInfo")) {
        New-Item -Path "$PathToLMPoliciesAdvertisingInfo" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesAdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value $One

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Let websites provide locally relevant content by accessing my language list'..."
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

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) send inking and typing data to Microsoft..."
    If (!(Test-Path "$PathToCUInputTIPC")) {
        New-Item -Path "$PathToCUInputTIPC" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToCUInputTIPC" -Name "Enabled" -Type DWord -Value $Zero

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Improve Inking & Typing Recognition..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value $Zero

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) View diagnostic data..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" -Name "EnableEventTranscript" -Type DWord -Value $Zero

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) feedback frequency..."
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
    Write-Output -Types "-", $TweakType -Status "Denying device access..."
    If (!(Test-Path "$PathToCUDeviceAccessGlobal\LooselyCoupled")) {
        New-Item -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Force | Out-Null
    }
    # Disable sharing information with unpaired devices
    Set-ItemProperty -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Name "Value" -Value "Deny"
    ForEach ($key in (Get-ChildItem "$PathToCUDeviceAccessGlobal")) {
        If ($key.PSChildName -EQ "LooselyCoupled") {
            Continue
        }
        Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Setting $($key.PSChildName) value to 'Deny' ..."
        Set-ItemProperty -Path ("$PathToCUDeviceAccessGlobal\" + $key.PSChildName) -Name "Value" -Value "Deny"
    }

    Write-Caption -Text "Background Apps"
    Enable-BackgroundAppsToogle
    }

    Write-Output -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Restricting Windows Update P2P downloads for Local Network only..."
    If (!(Test-Path "$PathToLMDeliveryOptimizationCfg")) {
        New-Item -Path "$PathToLMDeliveryOptimizationCfg" -Force | Out-Null
    }
    # [@] (0 = Off, 1 = Local Network only, 2 = Local Network private peering only)
    # [@] (3 = Local Network and Internet,  99 = Simply Download mode, 100 = Bypass mode)
    Set-ItemProperty -Path "$PathToLMDeliveryOptimizationCfg" -Name "DODownloadMode" -Type DWord -Value $One

    Write-Caption -Text "Troubleshooting"
    Write-Output -Types "+", $TweakType -Status "Enabling Automatic Recommended Troubleshooting, then notify me..."
    If (!(Test-Path "$PathToLMWindowsTroubleshoot")) {
        New-Item -Path "$PathToLMWindowsTroubleshoot" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMWindowsTroubleshoot" -Name "UserPreference" -Type DWord -Value 3

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows Spotlight Features..."
    If (!(Test-Path "$PathToCUPoliciesCloudContent")) {
        New-Item -Path "$PathToCUPoliciesCloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "ConfigureWindowsSpotlight" -Type DWord -Value 2
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "IncludeEnterpriseSpotlight" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnSettings" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Type DWord -Value $One

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Tailored Experiences..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value $One

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Third Party Suggestions..."
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableThirdPartySuggestions" -Type DWord -Value $One
    Set-ItemProperty -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value $One

    # Reference: https://forums.guru3d.com/threads/windows-10-registry-tweak-for-disabling-drivers-auto-update-controversy.418033/
    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) automatic driver updates..."
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
    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) some startup event traces (AutoLoggers)..."
    If (!(Test-Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener")) {
        New-Item -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWord -Value $Zero
    Set-ItemProperty -Path "$PathToLMAutoLogger\SQMLogger" -Name "Start" -Type DWord -Value $Zero

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: HotSpot Sharing'..."
    If (!(Test-Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Name "value" -Type DWord -Value $Zero

    Write-Output -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: Shared HotSpot Auto-Connect'..."
    If (!(Test-Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots")) {
        New-Item -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type DWord -Value $Zero

    Write-Output "Disabling Office Telemetry"
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "accesssolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "olksolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "onenotesolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "pptsolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "projectsolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "publishersolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "visiosolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "wdsolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedapplications" -Name "xlsolution" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" -Name "agave" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" -Name "appaddins" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" -Name "comaddins" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" -Name "documentfiles" -Type DWord -Value 1
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Software\Policies\microsoft\office\16.0\osm\preventedsolutiontypes" -Name "templatefiles" -Type DWord -Value 1

    Write-Output "Disabling telemetry tasks"
    schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
schtasks /end /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
schtasks /change /tn "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /end /tn "\Microsoft\Windows\Shell\FamilySafetyUpload"
schtasks /change /tn "\Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /end /tn "\Microsoft\Windows\Autochk\Proxy"
schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable
schtasks /end /tn "\Microsoft\Windows\Maintenance\WinSAT"
schtasks /change /tn "\Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\AitAgent"
schtasks /change /tn "\Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /end /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /change /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /end /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks /change /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /end /tn "\Microsoft\Windows\DiskFootprint\Diagnostics"
schtasks /change /tn "\Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /end /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
schtasks /change /tn "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /end /tn "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /end /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
schtasks /end /tn "\Microsoft\Windows\AppID\SmartScreenSpecific"
schtasks /change /tn "\Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /end /tn "\Microsoft\Windows\HelloFace\FODCleanupTask"
schtasks /change /tn "\Microsoft\Windows\HelloFace\FODCleanupTask" /disable
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClient"
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /end /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device"
schtasks /change /tn "\Microsoft\Windows\Device Information\Device" /disable
schtasks /end /tn "\Microsoft\Windows\Device Information\Device User"
schtasks /change /tn "\Microsoft\Windows\Device Information\Device User" /disable

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

Write-Output "Disabling Let’s finish setting up your device screen..."
Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
}
else {
    Write-Output "Windows will keep spying on you. Ratio."
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
        Write-Status -Types "*", "Service" -Status "Reverting the tweaks is set to '$Revert'."
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
    Import-Module -DisableNameChecking "$PSScriptRoot\lib\Title-Templates.psm1"
    Import-Module -DisableNameChecking "$PSScriptRoot\lib\Remove-ItemVerified.psm1"
    Import-Module -DisableNameChecking "$PSScriptRoot\lib\Remove-UWPApp.psm1"
    Import-Module -DisableNameChecking "$PSScriptRoot\lib\Set-ItemPropertyVerified.psm1"
    Import-Module -DisableNameChecking "$PSScriptRoot\lib\Show-MessageDialog.psm1"
    
    function Remove-MSEdge() {
        $PathToLMEdgeUpdate = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"
        $PathToLMUninstallMSEdge = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
        $PathToLMUninstallMSEdgeUpdate = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"
        $PathToLMUninstallMSEdgeWebView = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView"
    
        Write-Status -Types "+" -Status "Enabling uninstall button to Microsoft Edge..."
        Set-ItemPropertyVerified -Path "$PathToLMUninstallMSEdge", "$PathToLMUninstallMSEdgeUpdate", "$PathToLMUninstallMSEdgeWebView" -Name "NoRemove" -Type DWord -Value 0
    
        Write-Status -Types "@" -Status "Stopping all 'msedge' processes before uninstalling..."
        Get-Process -Name msedge | Stop-Process -PassThru -Force
    
        If (Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application") {
            ForEach ($FullName in (Get-ChildItem -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge*\Application\*\Installer\setup.exe").FullName) {
                Write-Status -Types "@" -Status "Uninstalling MS Edge from $FullName..."
                Start-Process -FilePath $FullName -ArgumentList "--uninstall", "--system-level", "--verbose-logging", "--force-uninstall" -Wait
            }
        } Else {
            Write-Status -Types "?" -Status "Edge folder does not exist anymore..." -Warning
        }
    
        If (Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore") {
            ForEach ($FullName in (Get-ChildItem -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore\*\Installer\setup.exe").FullName) {
                Write-Status -Types "@" -Status "Uninstalling MS Edge from $FullName..."
                Start-Process -FilePath $FullName -ArgumentList "--uninstall", "--system-level", "--verbose-logging", "--force-uninstall" -Wait
            }
        } Else {
            Write-Status -Types "?" -Status "EdgeCore folder does not exist anymore..." -Warning
        }
    
        Remove-UWPApp -AppxPackages @("Microsoft.MicrosoftEdge", "Microsoft.MicrosoftEdge.Stable", "Microsoft.MicrosoftEdge.*", "Microsoft.MicrosoftEdgeDevToolsClient")
        Set-ScheduledTaskState -State Disabled -ScheduledTasks @("\MicrosoftEdgeUpdateTaskMachineCore", "\MicrosoftEdgeUpdateTaskMachineUA", "\MicrosoftEdgeUpdateTaskUser*")
        Set-ServiceStartup -State 'Disabled' -Services @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")
    
        Write-Status -Types "@" -Status "Preventing Edge from reinstalling..."
        Set-ItemPropertyVerified -Path "$PathToLMEdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1
    
        Write-Status -Types "@" -Status "Deleting Edge appdata\local folders from current user..."
        Remove-ItemVerified -Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge*_*" -Recurse -Force | Out-Host
    
        Write-Status -Types "@" -Status "Deleting Edge from $env:SystemDrive\Program Files (x86)\Microsoft\..."
        Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge" -Recurse -Force | Out-Host
        # Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force | Out-Host
        Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force | Out-Host
        # Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeWebView" -Recurse -Force | Out-Host
        Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Temp" -Recurse -Force | Out-Host
    }
    
    $Ask = "Are you sure you want to remove Microsoft Edge from Windows?`nWill uninstall WebView2 and thus break many PWA (Progressive Web App) applications`n(e.g., Snapchat, Instagram...)`n`nYou can reinstall Edge anytime.`nNote: all users logged in will remain."
    
    switch (Show-Question -Title "Warning" -Message $Ask -BoxIcon "Warning") {
        'Yes' {
            Remove-MSEdge
        }
        'No' {
            Write-Host "Aborting..."
        }
        'Cancel' {
            Write-Host "Aborting..." # With Yes, No and Cancel, the user can press Esc to exit
        }
    }
} else {
    Write-Output "Microsoft Edge will not be uninstalled."
}





Write-Output "Do you want to optimize Task Scheduler tasks? (y/n)"
$confirm = Read-Host
if ($confirm -eq "y") {
    #Optimizes Task Scheduler tasks
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Set-Scheduled-TaskState.psm1"
Import-Module -DisableNameChecking $PSScriptRoot\include\lib\"Title-Templates.psm1"

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
        Write-Status -Types "*", "TaskScheduler" -Status "Reverting the tweaks is set to '$Revert'."
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
}
else {
    Write-Output "Network connectivity will not be optimized."
}
timeout /t 2