Import-Module -DisableNameChecking "$PSScriptRoot\Title-Templates.psm1"

function Get-CPU {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Switch]$NameOnly,
        [String]$Separator = '|'
    )

    try {
        $CPUInfo = Get-CimInstance -ClassName Win32_Processor
        $CPUName = $CPUInfo.Name.Trim()
        $CPUCoresAndThreads = "$($CPUInfo.NumberOfCores)C/$($env:NUMBER_OF_PROCESSORS)T"

        if ($NameOnly) {
            return $CPUName
        }

        return "$Env:PROCESSOR_ARCHITECTURE $Separator $CPUName $CPUCoresAndThreads"
    } catch {
        Write-Warning "Unable to retrieve CPU information."
    }
}

function Get-GPU {
    [CmdletBinding()]
    [OutputType([String])]
    param ()

    try {
        $GPU = (Get-CimInstance -Class Win32_VideoController).Name
        Write-Verbose "Video Info: $GPU"
        return $GPU
    } catch {
        Write-Warning "Unable to retrieve GPU information."
    }
}

function Get-RAM {
    [CmdletBinding()]
    [OutputType([String])]
    param ()

    try {
        $RamInGB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
        $RAMSpeed = (Get-CimInstance -ClassName Win32_PhysicalMemory)[0].Speed
        return "$RamInGB`GB ($RAMSpeed`MHz)"
    } catch {
        Write-Warning "Unable to retrieve RAM information."
    }
}

function Get-OSArchitecture {
    [CmdletBinding()]
    param (
        [String]$Architecture = (Get-ComputerInfo -Property OSArchitecture)
    )

    try {
        if ($Architecture -like "*64*bit*") {
            $Architecture = "x64"
        } elseif ($Architecture -like "*32*bit*") {
            $Architecture = "x86"
        } elseif ($Architecture -like "*ARM*64") {
            $Architecture = "arm64"
        } elseif ($Architecture -like "*ARM*") {
            $Architecture = "arm"
        } else {
            Write-Host "[?] Couldn't identify the System Architecture '$Architecture'. :/" -ForegroundColor Yellow
            $Architecture = $null
        }

        Write-Warning "$Architecture OS detected!"
        return $Architecture
    } catch {
        Write-Warning "Unable to retrieve OS architecture."
    }
}

function Get-OSDriveType {
    [CmdletBinding()]
    [OutputType([String])]
    param ()

    try {
        $SystemDriveType = Get-PhysicalDisk | Where-Object {
            $Disk = $_
            $Disk | Get-Disk | Get-Partition | Where-Object DriveLetter -EQ "$($env:SystemDrive[0])"
        } | Select-Object -ExpandProperty MediaType

        return $SystemDriveType
    } catch {
        Write-Warning "Unable to retrieve OS drive type."
    }
}

function Get-DriveSpace {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [String]$DriveLetter = $env:SystemDrive[0]
    )

    try {
        $SystemDrive = Get-PSDrive -Name $DriveLetter
        $AvailableStorage = $SystemDrive.Free / 1GB
        $UsedStorage = $SystemDrive.Used / 1GB
        $TotalStorage = $AvailableStorage + $UsedStorage
        return "$DriveLetter`: $([math]::Round($AvailableStorage, 1))/$([math]::Round($TotalStorage, 1)) GB ($([math]::Round(($AvailableStorage / $TotalStorage) * 100, 1))%)"
    } catch {
        Write-Warning "Unable to retrieve drive space information."
    }
}

function Get-SystemSpec {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [String]$Separator = '|'
    )

    try {
        Write-Status -Types "@" -Status "Loading system specs..."

        $WinVer = (Get-CimInstance -Class Win32_OperatingSystem).Caption -replace 'Microsoft ', ''
        $DisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
        $OldBuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
        $VersionDisplay = if ($DisplayVersion) { $DisplayVersion } else { $OldBuildNumber }

        return @( 
            Get-OSDriveType, 
            $Separator, 
            $WinVer, 
            "($VersionDisplay)", 
            $Separator, 
            Get-RAM, 
            $Separator, 
            Get-CPU -Separator $Separator, 
            $Separator, 
            Get-GPU
        )
    } catch {
        Write-Warning "Unable to retrieve system specifications."
    }
}
