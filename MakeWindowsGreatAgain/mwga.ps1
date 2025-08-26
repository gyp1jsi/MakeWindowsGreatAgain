# MakeWindowsGreatAgain
# This script is designed to enhance the Windows experience by removing unwanted apps, disabling telemetry and services, and applying various tweaks.

mode con: cols=82 lines=28

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
    Write-Output "        [1] - Uninstall apps                        [2] - Install WinGet"
    Write-Output ""
    Write-Output ""
    Write-Output "        [3] - Optimize Privacy                      [4] - Optimize Services"
    Write-Output ""
    Write-Output ""
    Write-Output "        [5] - Other Tweaks                          [6] - Rants"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "        [Q] - Quit"
    Write-Output ""
    Write-Output ""

    $key = Read-Host "Select an option and press Enter: "
    switch ($key) {
        1 {Uninstall-Apps}
        2 {Install-WinGet}
        3 {Optimize-Privacy}
        4 {Optimize-Services}
        5 {Other-Tweaks}
        6 {Rants}
        q {break}
    }
}
# Uninstall apps
function Uninstall-Apps {
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Uninstall Apps)"

    function BingApps {
            $Bing = @(
            "Microsoft.Bing"                         # Bing
            "Microsoft.BingFinance"                  # Finance
            "Microsoft.BingFoodAndDrink"             # Food And Drink
            "Microsoft.BingHealthAndFitness"         # Health And Fitness
            "Microsoft.BingNews"                     # News
            "Microsoft.BingSports"                   # Sports
            "Microsoft.BingTranslator"               # Translator
            "Microsoft.BingTravel"                   # Travel
            "Microsoft.BingWeather"                  # Weather
            "Microsoft.BingVisualSearch"             # Visual Search
            "Microsoft.BingWallpaper"                # Bing Wallpaper
            "Microsoft.BingWallpaperDiscovery"       # Bing Wallpaper Discovery
        )
        foreach ($App in $Bing) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Bing-related apps uninstalled."
         
        Uninstall-Apps
    }

    function XboxApps {
        $Xbox = @(
            "Microsoft.XboxGameCallableUI"            # Xbox Game Callable UI
            "Microsoft.XboxGameOverlay"               # Xbox Game Overlay
            "Microsoft.XboxGamingOverlay"             # Xbox Game Bar
            "Microsoft.XboxIdentityProvider"          # Xbox Identity Provider
            "Microsoft.XboxSpeechToTextOverlay"       # Xbox Speech To Text Overlay
            "Microsoft.Xbox.TCUI"                     # Xbox TCUI
            "Microsoft.XboxApp"                       # Xbox App
            "Microsoft.XboxGamePass"                  # Xbox Game Pass
            "Microsoft.XboxGamePassPC"                # Xbox Game Pass for PC
            "Microsoft.GamingServices"                # Gaming Services
            "Microsoft.GamingServices.Client"         # Gaming Services Client
            "Microsoft.GamingServices.UI"             # Gaming Services UI
            "Microsoft.GamingApp"                     # Gaming App
        )
        foreach ($App in $Xbox) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Xbox-related apps uninstalled."

        Uninstall-Apps
    }

    function Cortana {
        $Cortana = @(
            "Microsoft.Windows.Cortana"                # Cortana
            "Microsoft.Windows.CortanaExperience"      # Cortana Experience
            "Microsoft.Windows.CortanaSearch"          # Cortana Search
        )
        foreach ($App in $Cortana) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Cortana apps uninstalled."
         
        Uninstall-Apps
    }

    function OneDrive {
        $OneDrive = @(
            "Microsoft.OneDrive"                       # OneDrive
            "Microsoft.OneDrive.SkyDrive"              # OneDrive SkyDrive
            "Microsoft.OneDrive.SkyDrivePro"           # OneDrive SkyDrive Pro
        )
        foreach ($App in $OneDrive) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "OneDrive apps uninstalled."
         
        Uninstall-Apps
    }

    function FeedbackHub {
        $FeedbackHub = @(
            "Microsoft.WindowsFeedbackHub"             # Feedback Hub
            "Microsoft.WindowsFeedbackHubDev"          # Feedback Hub Dev
            "Microsoft.WindowsFeedbackHubBeta"         # Feedback Hub Beta
        )
        foreach ($App in $FeedbackHub) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Feedback Hub apps uninstalled."
         
        Uninstall-Apps
    }

    function OfficeApps {
        $OfficeApps = @(
            "Microsoft.Office.OneNote"                 # OneNote
            "Microsoft.Office.Outlook"                 # Outlook
            "Microsoft.Office.PowerPoint"              # PowerPoint
            "Microsoft.Office.Word"                    # Word
            "Microsoft.Office.Excel"                   # Excel
            "Microsoft.Office.Sway"                    # Sway
            "Microsoft.Office.Desktop"                 # Office Desktop
        )
        foreach ($App in $OfficeApps) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Office-related apps uninstalled."
         
        Uninstall-Apps
    }

    function YourPhone {
        $YourPhone = @(
            "Microsoft.YourPhone"                      # Your Phone
            "Microsoft.YourPhoneApp"                   # Your Phone App
            "Microsoft.YourPhoneExperience"            # Your Phone Experience
            "Microsoft.YourPhoneDesktop"               # Your Phone Desktop
        )
        foreach ($App in $YourPhone) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Your Phone apps uninstalled."
         
        Uninstall-Apps
    }

    function Teams {
        $Teams = @(
            "MicrosoftTeams"                           # Microsoft Teams
            "MicrosoftTeams.Desktop"                   # Microsoft Teams Desktop
            "MicrosoftTeams.Skype"                     # Microsoft Teams Skype
            "MicrosoftTeams.SkypeApp"                  # Microsoft Teams Skype App
        )
        foreach ($App in $Teams) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Microsoft Teams apps uninstalled."
         
        Uninstall-Apps
    }

    function MixedReality {
        $MixedReality = @(
            "Microsoft.MixedReality.Portal"            # Mixed Reality Portal
            "Microsoft.MixedReality.Toolkit"           # Mixed Reality Toolkit
            "Microsoft.MixedReality.Toolkit.Core"      # Mixed Reality Toolkit Core
            "Microsoft.MixedReality.Toolkit.Input"     # Mixed Reality Toolkit Input
            "Microsoft.MixedReality.Toolkit.UI"        # Mixed Reality Toolkit UI
        )
        foreach ($App in $MixedReality) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Mixed Reality apps uninstalled."
         
        Uninstall-Apps
    }

    function ThirdPartyApps {
        $ThirdParty = @(
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
            "*DisneyPlus*"
            "*Netflix*"                        # Netflix
            "*Spotify*"
        )
        foreach ($App in $ThirdParty) {
            Write-Verbose -Message ('Removing Package {0}' -f $App)
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
        Write-Output "Third-party apps uninstalled."
         
        Uninstall-Apps
    }

    function WindowsStore {
        Write-Output "Uninstalling Windows Store..."
        Get-AppxPackage -allusers WindowsStore | Remove-AppxPackage
        Write-Output "Windows Store uninstalled."
         
        Uninstall-Apps
    }

    function MicrosoftEdge {
        Write-Output "Uninstalling Microsoft Edge..."
        Get-AppxPackage -allusers Microsoft.MicrosoftEdge | Remove-AppxPackage
        Write-Output "Microsoft Edge uninstalled."
         
        Uninstall-Apps
    }

    function AllApps {
        # Uninstall all apps logic here
        Write-Output "Uninstalling all apps..."
        Get-AppxPackage | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Output "All apps uninstalled."
         
        Uninstall-Apps
    }
    Clear-Host
    Write-Output "                                Uninstall Apps"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "    [1] - Bing Apps                           [2] - Xbox Apps"
    Write-Output ""
    Write-Output ""
    Write-Output "    [3] - Cortana                             [4] - OneDrive"
    Write-Output ""
    Write-Output ""
    Write-Output "    [5] - Feedback Hub                        [6] - Office-related Apps"
    Write-Output ""
    Write-Output ""
    Write-Output "    [7] - Your Phone                          [8] - Teams"
    Write-Output ""
    Write-Output ""
    Write-Output "    [9] - 3D/Mixed Reality                    [10] - 3rd Party Apps"
    Write-Output ""
    Write-Output ""
    Write-Output "    [11] - Windows Store                      [12] - Microsoft Edge"
    Write-Output ""
    Write-Output ""
    Write-Output "                                 [A] - All Apps"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "    [B] - Go Back"
    Write-Output ""
    Write-Output ""



    $key = Read-Host "  Select an option and press Enter: "
    switch ($key) {
        1 {BingApps}
        2 {XboxApps}
        3 {Cortana}
        4 {OneDrive}
        5 {FeedbackHub}
        6 {OfficeApps}
        7 {YourPhone}
        8 {Teams}
        9 {MixedReality}
        10 {ThirdPartyApps}
        11 {WindowsStore}
        12 {MicrosoftEdge}
        a {AllApps}
        b {Show-Menu}
    }
    
}

# Install WinGet
function Install-WinGet {
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Install WinGet)"
    Clear-Host
    Write-Output "                                Install WinGet"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    
    Install-Script winget-install -Force

    Clear-Host
    Write-Output "                                Install WinGet"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "                    WinGet has been installed successfully."
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "                                 [B] - Go Back"
    Write-Output ""

        $key = Read-Host "  Select an option and press Enter: "
    switch ($key) {
        b {Show-Menu}
    }
    
}

# Optimize Privacy
function Optimize-Privacy {
    function Telemetry-Registry {
        Clear-Host
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 4294967295
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 2
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 30
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
        
        Write-Output "Telemetry and data collection registry keys have been disabled."

        Optimize-Privacy


    }

    function Telemetry-Services {
        Clear-Host
        $services = @(
            "DiagTrack",                              # Connected User Experiences and Telemetry
            "dmwappushservice",                       # DMWAppPushService
            "WMPNetworkSvc",                          # Windows Media Player Network Sharing Service
            "WSearch",                                # Windows Search
            "WMPNetworkSvc",                          # Windows Media Player Network Sharing Service
            "WerSvc"                                  # Windows Error Reporting Service
        )
        foreach ($service in $services) {
            Write-Verbose -Message ('Disabling Service {0}' -f $service)
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        }
        Write-Output "Telemetry and data collection services have been disabled."
         
        Optimize-Privacy

    }

    function Telemetry-ScheduledTasks {
        Clear-Host
        $tasks = @(
            "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "Microsoft\Windows\Autochk\Proxy",
            "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "Microsoft\Windows\Feedback\Siuf\DmClient",
            "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
            "Microsoft\Windows\Windows Error Reporting\QueueReporting",
            "Microsoft\Windows\Application Experience\MareBackup",
            "Microsoft\Windows\Application Experience\StartupAppTask",
            "Microsoft\Windows\Application Experience\PcaPatchDbTask",
            "Microsoft\Windows\Maps\MapsUpdateTask"
            )

        foreach ($task in $tasks) {
            $parts = $task -split '\\'
            $taskPath = "\" + ($parts[0..($parts.Length - 2)] -join '\') + "\"
            $taskName = $parts[-1]
            Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
        }
                Write-Output "Telemetry scheduled tasks have been disabled."
                Optimize-Privacy

    }

    Clear-Host
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Optimize Privacy)"
    Write-Output ""
    Write-Output "                                Optimize Privacy"
    Write-Output "" 
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "      [1] - Disable Telemetry and Data Collection registry keys"
    Write-Output ""
    Write-Output ""
    Write-Output "      [2] - Disable Telemetry and Data Collection services"
    Write-Output ""
    Write-Output ""
    Write-Output "      [3] - Disable Telemetry and Data Collection scheduled tasks"
    Write-Output ""
    Write-Output "===================================================================================="
    Write-Output ""
    Write-Output "                                   [B] - Go Back"
    Write-Output ""

    $key = Read-Host "  Select an option and press Enter: "
    switch ($key) {
        1 {Telemetry-Registry}
        2 {Telemetry-Services}
        3 {Telemetry-ScheduledTasks}
        b {Show-Menu}
    }
}   

# Optimize Services
function Optimize-Services {

    function ManualServices {
        if (-not (Test-Path "C:\MakeWindowsGreatAgain\backup")) {
            mkdir "C:\MakeWindowsGreatAgain\backup"
        }
        # Saves a copy of running services before running this part to be restored if needed
        # Get all services and filter by start type
        $automaticServices = Get-Service | Where-Object { $_.StartType -eq "Automatic" } | Select-Object -ExpandProperty Name
        $manualServices = Get-Service | Where-Object { $_.StartType -eq "Manual" } | Select-Object -ExpandProperty Name

        # Define the file path for the output
        $AutoOutput = "C:\MakeWindowsGreatAgain\backup\autoserv.txt"
        $ManOutput = "C:\MakeWindowsGreatAgain\backup\manserv.txt"

        # Create or overwrite the output file
        $automaticServices | Out-File -FilePath $AutoOutput
        $manualServices | Out-File -FilePath $ManOutput

        $ServicesToManual = @(
            "aarsvc_2b9ad"
            "alg"
            "appidsvc"
            "appinfo"
            "appmgmt"
            "appreadiness"
            "appxsvc"
            "axinstsv"
            "bcastdvruserservice_2b9ad"
            "btagservice"
            "bthavctpsvc"
            "bthserv"
            "bits"
            "bluetoothuserservice_2b9ad"
            "captureservice_2b9ad"
            "cbdhsvc_2b9ad"
            "cdpsvc"
            "certpropsvc"
            "clipsvc"
            "comsysapp"
            "consentuxusersvc_2b9ad"
            "cryptsvc"
            "cscservice"
            "defragsvc"
            "deviceassociationbrokersvc_2b9ad"
            "deviceassociationservice"
            "deviceinstall"
            "devicepickerusersvc_2b9ad"
            "devquerybroker"
            "diagnosticshub.standardcollector.service"
            "diagsvc"
            "dispbrokerdesktopsvc"
            "displaypolicyservice"
            "dmwappushservice"
            "dot3svc"
            "dsmsvc"
            "dps"
            "dssvc"
            "dusmsvc"
            "efs"
            "eaphost"
            "edgeupdate"
            "edgeupdatem"
            "embeddedmode"
            "entappsvc"
            "eventlog"
            "eventsystem"
            "fax"
            "fdrespub"
            "fhsvc"
            "fontcache"
            "frameserver"
            "graphicsperfsvc"
            "gupdate"
            "gupdatem"
            "hvhost"
            "icssvc"
            "ikeext"
            "installservice"
            "iphlpsvc"
            "ipxlatcfgsvc"
            "ktmrm"
            "lanmanserver"
            "lanmanworkstation"
            "licensemanager"
            "lfsvc"
            "lltdsvc"
            "lmhosts"
            "lxpsvc"
            "messagingservice_2b9ad"
            "msdtc"
            "msiinstaller"
            "msiserver"
            "msiscsi"
            "mskeyboardfilter"
            "mozillamaintenance"
            "ncasvc"
            "ncbservice"
            "ncdautosetup"
            "naturalauthentication"
            "netman"
            "netprofm"
            "netsetupsvc"
            "ngcctnrsvc"
            "ngcsvc"
            "nlasvc"
            "nsi"
            "nvcontainerlocalsystem"
            "nvdisplay.containerlocalsystem"
            "p2pimsvc"
            "p2psvc"
            "pcasvc"
            "peerdistsvc"
            "perfhost"
            "phonesvc"
            "pimindexmaintenancesvc_2b9ad"
            "pla"
            "plugplay"
            "pnrpautoreg"
            "pnrpsvc"
            "policyagent"
            "printnotify"
            "printworkflowusersvc_2b9ad"
            "profsvc"
            "pushtoinstall"
            "qwav"
            "rasauto"
            "retaildemo"
            "rmsvc"
            "rtkbtmanserv"
            "scdevicesenum"
            "scardsvr"
            "scpolicysvc"
            "sdrrsvc"
            "seclogon"
            "semgrsvc"
            "sens"
            "sense"
            "sensordataservice"
            "sensorservice"
            "sensrsvc"
            "sharedaccess"
            "sharedrealitysvc"
            "shellhwdetection"
            "spectrum"
            "staterepository"
            "storsvc"
            "ssdpsrv"
            "sstpsvc"
            "surfshark wireguard"
            "svsvc"
            "sysmain"
            "tabletinputservice"
            "tapisrv"
            "themes"
            "tieringengineservice"
            "timebrokersvc"
            "tokenbroker"
            "troubleshootingsvc"
            "trustedinstaller"
            "umrdpservice"
            "unistoresvc_2b9ad"
            "upnphost"
            "usosvc"
            "vacsvc"
            "vds"
            "vmicguestinterface"
            "vmicheartbeat"
            "vmickvpexchange"
            "vmicrdv"
            "vmicshutdown"
            "vmictimesync"
            "vmicvmsession"
            "vmicvss"
            "vss"
            "walletservice"
            "warpjitsvc"
            "wbengine"
            "wbiosrvc"
            "w32time"
            "waasmedicsvc"
            "webclient"
            "wecsvc"
            "wephostsvc"
            "wersvc"
            "wfdsvc"
            "wiarpc"
            "winhttpautoproxysvc"
            "winrm"
            "wisvc"
            "wlansvc"
            "wlanmanagersvc"
            "wmansvc"
            "wmpnetworksvc"
            "wpcmonsvc"
            "wpnservice"
            "workfolderssvc"
            "wsearch"
            "wuauserv"
            "wudfsvc"
            "wwansvc"
            "xblauthmanager"
            "xblgamesave"
            "xboxgipsvc"
            "xboxnetapisvc"
        )
        foreach ($Service in $ServicesToManual) {
            Write-Verbose -Message ('Setting Service {0} to Manual' -f $Service)
            Set-Service -Name $Service -StartupType Manual -ErrorAction SilentlyContinue
        }

        Optimize-Services

    }

    function DisabledServices {
        if (-not (Test-Path "C:\MakeWindowsGreatAgain\backup")) {
            mkdir "C:\MakeWindowsGreatAgain\backup"
        }
        # Saves a copy of running services before running this part to be restored if needed
        $disabledServices = Get-Service | Where-Object { $_.StartType -eq "Disabled" } | Select-Object -ExpandProperty Name
        $DisOutput = "C:\MakeWindowsGreatAgain\backup\disserv.txt"
        # Create or overwrite the output file
        $disabledServices | Out-File -FilePath $DisOutput

        $ServicesToDisabled = @(
        "DiagTrack"                                
        "diagnosticshub.standardcollector.service"  
        "dmwappushservice"                          
        "GraphicsPerfSvc"                           
        "HomeGroupListener"                         
        "HomeGroupProvider"                         
        "lfsvc"                                    
        "MapsBroker"                               
        "PcaSvc"                                  
        "RemoteAccess"                         
        "RemoteRegistry"                           
        "RetailDemo"                        
        "TrkWks"                             
        "AJRouter"
        "AppVClient"
        "AssignedAccessManagerSvc"
        "cphs"
        "cplspcon"
        "DialogBlockingService"
        "esifsvc"
        "LMS"
        "MapsBroker"
        "NetTcpPortSharing"
        "RemoteAccess"
        "RemoteRegistry"
        "RstMwService"
        "shpamsvc"
        "tzautoupdate"
        "UevAgentService"
        "XTU3SERVICE"
        "NortonSecurity"
        "nsWscSvc"
        "FvSvc"
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
        "HomeGroupListener"
        )
        foreach ($Service in $ServicesToDisabled) {
            Write-Verbose -Message ('Setting Service {0} to Disabled' -f $Service)
            Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
        }

        Optimize-Services

    }

    function OEMServices {
        function AsusServices {
            Clear-Host
            Write-Output "Disabling ASUS Services..."
            $asusServices = @(
                "AsusService"
                "AsusFanControlService"
                "AsusUpdateService"
                "AsusSystemControlService"
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
            )
            foreach ($service in $asusServices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
            Write-Output "ASUS Services have been disabled."
             
            Optimize-Services
        }

        function DellServices {
            Clear-Host
            Write-Output "Disabling Dell Services..."
            $dellServices = @(
                "DellDataVault"
                "DellSupportAssistAgent"
                "DellSupportAssistRemediate"
                "DellUpdateService"
            )
            foreach ($service in $dellServices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
            Write-Output "Dell Services have been disabled."
             
            Optimize-Services
        }

        function HPServices {
            Clear-Host
            Write-Output "Disabling HP Services..."
            $hpServices = @(
                "HPSupportSolutionsFrameworkService"
                "HPSupportSolutionsFrameworkService_2b9ad"
                "HPDeviceMonitoringFramework"
                "HPNetworkCommunicationsService"
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
            )
            foreach ($service in $hpServices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
            Write-Output "HP Services have been disabled."
             
            Optimize-Services
        }

        function LenovoServices {
            Clear-Host
            Write-Output "Disabling Lenovo Services..."
            $lenovoServices = @(
                "LenovoVantageService"
                "LenovoSystemInterfaceFoundationService"
                "LenovoUpdateAgent"
                "LenovoPowerManagementService"
            )
            foreach ($service in $lenovoServices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
            Write-Output "Lenovo Services have been disabled."
             
            Optimize-Services
        }

        function MSIServices {
            Clear-Host
            Write-Output "Disabling MSI Services..."
            $msiServices = @(
                "MSIService"
                "MSIUpdateService"
                "MSIInstaller"
                "MSIHelperService"
                "Micro Star SCM"
                "MSI_Center_Service"
                "MSI Foundation Service"
                "MSI_VoiceControl_Service"
                "Mystic_Light_Service"
                "NahimicService"        
            )
            foreach ($service in $msiServices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
            Write-Output "MSI Services have been disabled."
             
            Optimize-Services
        }

        function SamsungServices {
            Clear-Host
            Write-Output "Disabling Samsung Services..."
            $samsungServices = @(
                "SamsungDeviceService"
                "SamsungUpdateService"
                "SamsungSmartSwitchService"
                "SamsungLinkService"
            )
            foreach ($service in $samsungServices) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            }
            Write-Output "Samsung Services have been disabled."
             
            Optimize-Services
        }


        Clear-Host
        $host.UI.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (OEM Services)"
        Write-Output ""
        Write-Output "                                OEM Services"
        Write-Output ""
        Write-Output "=================================================================================="
        Write-Output ""
        Write-Output "      [1] - Disable ASUS Services             [2] - Disable Dell Services"
        Write-Output ""
        Write-Output ""
        Write-Output "      [3] - Disable HP Services               [4] - Disable Lenovo Services"
        Write-Output ""
        Write-Output ""
        Write-Output "      [5] - Disable MSI Services              [6] - Disable Samsung Services"
        Write-Output ""
        Write-Output "==================================================================================="
        Write-Output ""
        Write-Output "                                [B] - Go Back"
        Write-Output ""
        $key = Read-Host "  Select an option and press Enter: "
        switch ($key) {
            1 {AsusServices}
            2 {DellServices}
            3 {HPServices}
            4 {LenovoServices}
            5 {MSIServices}
            6 {SamsungServices}
            b {Optimize-Services}
        }
    }
    
    Clear-Host
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Optimize Services)"
    Write-Output ""
    Write-Output "                                Optimize Services"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "      [1] - Set Services to Manual                [2] - Set Services to Disabled"
    Write-Output ""
    Write-Output ""
    Write-Output "      [3] - OEM Services"
    Write-Output ""
    Write-Output "==================================================================================="
    Write-Output ""
    Write-Output "      [B] - Go Back"
    Write-Output ""
    
    $key = Read-Host "  Select an option and press Enter: "
    switch ($key) {
        1 {ManualServices}
        2 {DisabledServices}
        3 {OEMServices}
        b {Show-Menu}
    }
    

}   

# Other Tweaks
function Other-Tweaks {

    function Disable-Teredo {
        Clear-Host
        Write-Output "Disabling Teredo..."
        Set-NetTeredoConfiguration -Type Disabled
        Write-Output "Teredo has been disabled."
         
        Other-Tweaks
    }

    function Set-SecurityUpdatesOnly {
        Clear-Host
        Write-Output "Setting updates to security only..."
            reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "BranchReadinessLevel" /t REG_DWORD /d "20" /f
            reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "365" /f
            reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferQualityUpdatesPeriodInDays " /t REG_DWORD /d "4" /f
             
            Other-Tweaks
    }

    function Disable-NvidiaTelemetry {
        Clear-Host
        Write-Output "Disabling NVIDIA Telemetry..."
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f
        reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f
        reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f
        reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f
        reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f
        schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        schtasks /change /disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
        Write-Output "NVIDIA Telemetry has been disabled."
         
        Other-Tweaks
    }
    function Disable-Hibernation {
        Clear-Host
        Write-Output "Disabling Hibernation..."
        powercfg.exe /hibernate off
        Write-Output "Hibernation has been disabled."
         
        Other-Tweaks
    }

    function Disable-DeliveryOptimization {
        Clear-Host
        Write-Output "Disabling Windows Update Delivery Optimization..."
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
        Write-Output "Windows Update Delivery Optimization has been disabled."
         
        Other-Tweaks
    }

    function Optimize-Connectivity {
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
         
        Other-Tweaks
    }

    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Other Tweaks)"
    Clear-Host
    Write-Output ""
    Write-Output "                                Other Tweaks"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "      [1] - Disable Teredo"
    Write-Output ""
    Write-Output ""
    Write-Output "      [2] - Set updates to security only"
    Write-Output ""
    Write-Output ""
    Write-Output "      [3] - Disable NVIDIA Telemetry"
    Write-Output ""
    Write-Output ""
    Write-Output "      [4] - Disable Hibernation"
    Write-Output ""
    Write-Output ""
    Write-Output "      [5] - Disable Windows Update Delivery Optimization"
    Write-Output ""
    Write-Output ""
    Write-Output "      [6] - Optimize connectivity"
    Write-Output ""
    Write-Output "==================================================================================="
    Write-Output ""
    Write-Output "                                 [B] - Go Back"
    Write-Output ""

    
    $key = Read-Host "  Select an option and press Enter:"
    switch ($key) {
        1 {Disable-Teredo}
        2 {Set-SecurityUpdatesOnly}
        3 {Disable-NvidiaTelemetry}
        4 {Disable-Hibernation}
        5 {Disable-DeliveryOptimization}
        6 {Optimize-Connectivity}
        b {Show-Menu}
    }
}

# Rants
function Rants {
    $host.ui.RawUI.WindowTitle = "MakeWindowsGreatAgain 2.1.0 - 2025.09.01 (Rants)"
    Clear-Host
    Write-Output ""
    Write-Output "                                    Rants"
    Write-Output ""
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "  I have grown up a lot during the past years, and I have realized that life is"
    Write-Output "      too short to waste time being angry about things I cannot change."
    write-Output ""
    Write-Output "      I can still criticize what I do not like, but I will not waste my time"
    Write-Output "    hating on people that do not impact my life at all. I can instead focus on"
    Write-Output "          myself and my life, making it the life I want it to be."
    Write-Output ""
    Write-Output "       Be stronger than your excuses, and do not have fear to try and fail."
    Write-Output "                        Does hate even make you proud?"
    Write-Output ""
    Write-Output "                                   -gypijsi"
    Write-Output "" 
    Write-Output "=================================================================================="
    Write-Output ""
    Write-Output "                                 [B] - Go Back"
    Write-Output ""
    
    $key = Read-Host "  Select an option and press Enter: "
    switch ($key) {
        b {Show-Menu}
    }
}

Show-Menu