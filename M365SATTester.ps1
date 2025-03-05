#Requires -Version 5.1
function ExecuteM365SAT
{
	Import-Module .\M365SAT.psd1

	<# MAKE CHANGES ONLY BELOW #>

	#CSV Report
	# Get-M365SATReport -OutPath "C:\Out" -Username "example@example.org" -EnvironmentType M365,AZURE -Modules "All" -LicenseMode "E3" -LicenseLevel "All" -reportType "CSV" -AllowLogging -LocalMode -SkipChecks 
	#HTML Report
	# Get-M365SATReport -OutPath "C:\Out" -Username "example@example.org" -EnvironmentType AZURE -Modules "All" -LicenseMode "All" -LicenseLevel "All" -reportType "HTML" -AllowLogging -LocalMode -SkipChecks
	
	<#This is for Windows#>
	#Get-M365SATReport -OutPath "C:\Out" -Username "example@example.org" -EnvironmentType M365,AZURE -Modules "All" -LicenseMode "E3" -LicenseLevel "All" -reportType "CSV" -AllowLogging -LocalMode -SkipChecks
	
	<#This is for Linux#>
	Get-M365SATReport -OutPath "/home/yourname/m365sat/out" -Username "example@example.org" -EnvironmentType M365,AZURE -Modules "All" -LicenseMode "E3" -LicenseLevel "All" -reportType "CSV" -AllowLogging -LocalMode -SkipChecks
	
	<#This is for MacOSX#>
	#Get-M365SATReport -OutPath "/home/yourname/m365sat/out" -Username "example@example.org" -EnvironmentType M365,AZURE -Modules "All" -LicenseMode "E3" -LicenseLevel "All" -reportType "CSV" -AllowLogging -LocalMode -SkipChecks

	<# END OF MAKING CHANGES #>
	
	Remove-Module M365SAT -Force
}

function Get-PSEnvironmentInfo {
    <#
    .SYNOPSIS
    Gets information about the PowerShell version and operating system environment
    
    .DESCRIPTION
    Returns an object with two properties:
    - PowerShellVersion: Major version of PowerShell (e.g., 5 or 7)
    - OperatingSystem: Detected OS (Windows, Linux, macOS, or Linux/macOS if undifferentiated)
    
    .EXAMPLE
    Get-PSEnvironmentInfo
    Returns: PowerShellVersion OperatingSystem
                        5 Windows
    #>
    
    # Get PowerShell major version
    $psVersion = $PSVersionTable.PSVersion.Major

    # Detect operating system
    $OS = "Unknown"
    
    # First check automatic variables (works in PowerShell 6+)
    if ($IsWindows -or $env:OS -eq 'Windows_NT' -or [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or $psVersion -eq 5) {
        $OS = "Windows"
    }
    elseif ($IsLinux -or [System.Environment]::OSVersion.Platform -eq 'Unix') {
        $OS = "Linux"
    }
    elseif ($IsMacOS -or [System.Environment]::OSVersion.Platform -eq 'MacOSX') {
        $OS = "macOS"
    }
    else {
        # Fallback checks for PowerShell 5.1 or edge cases
        try {
            $uname = (uname -s 2>$null)
            switch -Wildcard ($uname) {
                'Linux*'  { $OS = "Linux" }
                'Darwin*'  { $OS = "macOS" }
            }
        }
        catch {
            # Final fallback to .NET PlatformID
            $platform = [System.Environment]::OSVersion.Platform
            if ($platform -eq 'Unix') {
                $os = "Linux/macOS"
            }
        }
    }

    # Return structured object
    [PSCustomObject]@{
        PowerShellVersion = $psVersion
        OperatingSystem   = $OS
    }
}

#The script is being designed to work with PowerShell 5.1 where there is no automatic detection of the operating system. For PowerShell 7 $IsLinux $IsWindows can be used.
function CheckAdminPrivBeta
{
	$OS = Get-PSEnvironmentInfo
	Write-Host "Your OS: $($OS.OperatingSystem)"
	# Check if script is running as Adminstrator and if not use RunAs
	if ($OS.OperatingSystem -eq 'Windows'){
		Write-Host "[+] Your OS is: $($OS.OperatingSystem) running PowerShell: $($OS.PowerShellVersion)"
		Write-Host "[...] Checking if the script is running as Administrator"
		$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
		if (-not $IsAdmin)
		{
			Write-Warning "[!] Program needs Administrator Rights! Trying to Elevate to Admin..."
			Start-Process powershell -Verb runas -ArgumentList "-NoExit -c cd '$pwd'; .\M365SATTester.ps1"
		}
	}
	elseif ($OS.OperatingSystem -eq 'Linux')
	{
		Write-Host "[+] Your OS is: $($OS.OperatingSystem) running PowerShell: $($OS.PowerShellVersion)" -ForegroundColor Green
		ExecuteM365SAT
	}
	elseif($OS.OperatingSystem -eq "MacOSX")
	{
		Write-Host "[+] Your OS is: $($OS.OperatingSystem) running PowerShell: $($OS.PowerShellVersion)" -ForegroundColor Green
		ExecuteM365SAT
	}
	else
	{
		Write-Host "Could not identify the Operating System!"
	}
}
CheckAdminPrivBeta