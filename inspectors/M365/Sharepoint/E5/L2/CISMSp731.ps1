# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp731
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp731"
        ID               = "7.3.1"
        Title            = "(L2) Ensure Office 365 SharePoint infected files are disallowed for download"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams protects your organization from inadvertently sharing malicious files. When an infected file is detected, that file is blocked so that no one can open, copy, move, or share it until further actions are taken by the organization's security team."
        Impact           = "The only potential impact associated with implementation of this setting is potential inconvenience associated with the small percentage of false positive detections that may occur."
        Remediation 	 = 'Set-SPOTenant -DisallowInfectedFileDownload $true'
        References       = @(
            @{ 'Name' = 'Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/turn-on-mdo-for-spo-odb-and-teams?view=o365-worldwide' },
            @{ 'Name' = 'Built-in virus protection in SharePoint Online, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/virus-detection-in-spo?view=o365-worldwide' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp731
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$DNAIFSP = Get-PnPTenant | Select-Object DisallowInfectedFileDownload
			if ($DNAIFSP.DisallowInfectedFileDownload -match 'False')
			{
				$DNAIFSP | Format-Table -AutoSize | Out-File "$path\CISMSp731-PnPTenant.txt"
				$endobject = Build-CISMSp731 -ReturnedValue ("DisallowInfectedFileDownload: $($DNAIFSP.DisallowInfectedFileDownload)") -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp731 -ReturnedValue ("DisallowInfectedFileDownload: $($DNAIFSP.DisallowInfectedFileDownload)") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			$DNAIFSP = Get-SPOTenant | Select-Object DisallowInfectedFileDownload
			if ($DNAIFSP.DisallowInfectedFileDownload -match 'False')
			{
				$DNAIFSP | Format-Table -AutoSize | Out-File "$path\CISMSp731-SPOTenant.txt"
				$endobject = Build-CISMSp731 -ReturnedValue ("DisallowInfectedFileDownload: $($DNAIFSP.DisallowInfectedFileDownload)") -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp731 -ReturnedValue ("DisallowInfectedFileDownload: $($DNAIFSP.DisallowInfectedFileDownload)") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp731 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp731