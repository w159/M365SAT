# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp729
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp729"
        ID               = "7.2.9"
        Title            = "(L1) Ensure guest access to a site or OneDrive will expire automatically"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "60 and false"
        ExpectedValue    = "30 and true"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "This setting ensures that guest users automatically lose access to sites or OneDrive after a set period, minimizing risks of prolonged unauthorized access."
        Impact           = "Site collection administrators will have to renew access to guests who still need access after 30 days. They will receive an e-mail notification once per week about guest access that is about to expire."
        Remediation 	 = 'Set-SPOTenant -ExternalUserExpireInDays 30 -ExternalUserExpirationRequired $True'
        References       = @(
            @{ 'Name' = 'Manage sharing settings for SharePoint and OneDrive in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off#change-the-organization-level-external-sharing-setting' },
            @{ 'Name' = 'Managing SharePoint Online Security: A Team Effort'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/community/sharepoint-security-a-team-effort' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp729
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant | Format-Table ExternalUserExpirationRequired, ExternalUserExpireInDays
			if ($SharepointSetting.ExternalUserExpireInDays -igt 30)
			{
				$AffectedOptions += "ExternalUserExpireInDays: $($SharepointSetting.ExternalUserExpireInDays)"
			}
			if ($SharepointSetting.ExternalUserExpirationRequired -ne $True)
			{
				$AffectedOptions += "ExternalUserExpirationRequired: False"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp729-SPOTenant.txt"
				$endobject = Build-CISMSp729 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp729 -ReturnedValue "ExternalUserExpireInDays: $($SharepointSetting.ExternalUserExpireInDays) \n ExternalUserExpirationRequired: True" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant | Format-Table ExternalUserExpirationRequired, ExternalUserExpireInDays
			if ($SharepointSetting.ExternalUserExpireInDays -igt 30)
			{
				$AffectedOptions += "ExternalUserExpireInDays: $($SharepointSetting.ExternalUserExpireInDays)"
			}
			if ($SharepointSetting.ExternalUserExpirationRequired -ne $True)
			{
				$AffectedOptions += "ExternalUserExpirationRequired: False"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp729-SPOTenant.txt"
				$endobject = Build-CISMSp729 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp729 -ReturnedValue "ExternalUserExpireInDays: $($SharepointSetting.ExternalUserExpireInDays) \n ExternalUserExpirationRequired: True" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null		
		}
	}
	catch
	{
		$endobject = Build-CISMSp729 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp729