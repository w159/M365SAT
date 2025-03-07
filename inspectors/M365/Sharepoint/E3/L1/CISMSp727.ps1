# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp727
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp727"
        ID               = "7.2.7"
        Title            = "(L1) Ensure link sharing is restricted in SharePoint and OneDrive"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "Only people in your organization (Internal)"
        ExpectedValue    = "Direct"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By defaulting to sharing links for specific people, users are encouraged to consider the principle of least privilege, ensuring content is only shared with intended recipients and not broadly accessible."
        Impact           = "Without restrictions, sensitive content may be inadvertently shared with unintended audiences, increasing the risk of data exposure."
        Remediation	 	 = 'Set-SPOTenant -DefaultSharingLinkType Direct'
        References       = @(
            @{ 'Name' = 'Set-SPOTenant Documentation'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp727
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant
			if ($SharepointSetting.DefaultSharingLinkType -eq "Internal")
			{
				$AffectedOptions += "DefaultSharingLinkType: $($SharepointSetting.DefaultSharingLinkType)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp727-SPOTenant.txt"
				$endobject = Build-CISMSp727 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp727 -ReturnedValue "DefaultSharingLinkType: $($SharepointSetting.DefaultSharingLinkType)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant
			if ($SharepointSetting.DefaultSharingLinkType -eq "Internal")
			{
				$AffectedOptions += "DefaultSharingLinkType: $($SharepointSetting.DefaultSharingLinkType)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp727-SPOTenant.txt"
				$endobject = Build-CISMSp727 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp727 -ReturnedValue "DefaultSharingLinkType: $($SharepointSetting.DefaultSharingLinkType)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}

	}
	catch
	{
		$endobject = Build-CISMSp727 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp727