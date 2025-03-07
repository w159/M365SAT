# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp724
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp724"
        ID               = "7.2.4"
        Title            = "(L2) Ensure OneDrive content sharing is restricted"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "Anyone (ExternalUserAndGuestSharing)"
        ExpectedValue    = "ExternalUserSharingOnly or lower"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "OneDrive, designed for end-user cloud storage, provides less oversight compared to SharePoint. This autonomy can lead to risks such as inadvertent sharing of sensitive information. Restricting external OneDrive sharing encourages tighter controls and oversight by requiring content to be shared via SharePoint folders."
        Impact           = "Users will be required to take additional steps to share OneDrive content or use other official channels."
        Remediation 	 = 'Set-SPOTenant -OneDriveSharingCapability Disabled'
        References       = @(
            @{ 'Name' = 'Manage Sharing Settings for SharePoint and OneDrive'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off?WT.mc_id=365AdminCSH_spo' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp724
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant | Format-List OneDriveSharingCapability
			if ($SharepointSetting.OneDriveSharingCapability -eq "ExternalUserAndGuestSharing")
			{
				$AffectedOptions += "SharingCapability: $($SharepointSetting.OneDriveSharingCapability)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp724-SPOTenant.txt"
				$endobject = Build-CISMSp724 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp724 -ReturnedValue "SharingCapability: $($SharepointSetting.OneDriveSharingCapability)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant | Format-List OneDriveSharingCapability
			if ($SharepointSetting.OneDriveSharingCapability -eq "ExternalUserAndGuestSharing")
			{
				$AffectedOptions += "SharingCapability: $($SharepointSetting.OneDriveSharingCapability)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp724-SPOTenant.txt"
				$endobject = Build-CISMSp724 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp724 -ReturnedValue "SharingCapability: $($SharepointSetting.OneDriveSharingCapability)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp724 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp724