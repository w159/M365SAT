# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp7210
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp7210"
        ID               = "7.2.10"
        Title            = "(L1) Ensure reauthentication with verification code is restricted"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "False and 30"
        ExpectedValue    = "True and 15"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Increasing the frequency of reauthentication for guests ensures that their access to sensitive data is limited to a reasonable time frame, reducing the risk of prolonged unauthorized access."
        Impact           = "Guests who use Microsoft 365 in their organization can sign in using their work or school account to access the site or document. After the one-time passcode for verification has been entered for the first time, guests will authenticate with their work or school account and have a guest account created in the host's organization."
        Remediation	 	 = 'Set-SPOTenant -EmailAttestationRequired $true -EmailAttestationReAuthDays 15'
        References       = @(
            @{ 'Name' = 'Secure external sharing recipient experience'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/what-s-new-in-sharing-in-targeted-release' },
            @{ 'Name' = 'Manage sharing settings for SharePoint and OneDrive in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off#change-the-organization-level-external-sharing-setting' },
            @{ 'Name' = 'Email one-time passcode authentication'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp7210
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant | Format-Table  EmailAttestationRequired, EmailAttestationReAuthDays
			if ($SharepointSetting.EmailAttestationRequired -ne $True)
			{
				$AffectedOptions += "EmailAttestationRequired: False"
			}
			if ($SharepointSetting.EmailAttestationReAuthDays -igt 15)
			{
				$AffectedOptions += "EmailAttestationReAuthDays: $($SharepointSetting.EmailAttestationReAuthDays)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7210-SPOTenant.txt"
				$endobject = Build-CISMSp7210 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp7210 -ReturnedValue "EmailAttestationRequired: False \n EmailAttestationReAuthDays: $($SharepointSetting.EmailAttestationReAuthDays)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant | Format-Table  EmailAttestationRequired, EmailAttestationReAuthDays
			if ($SharepointSetting.EmailAttestationRequired -ne $True)
			{
				$AffectedOptions += "EmailAttestationRequired: False"
			}
			if ($SharepointSetting.EmailAttestationReAuthDays -igt 15)
			{
				$AffectedOptions += "EmailAttestationReAuthDays: $($SharepointSetting.EmailAttestationReAuthDays)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7210-SPOTenant.txt"
				$endobject = Build-CISMSp7210 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp7210 -ReturnedValue "EmailAttestationRequired: False \n EmailAttestationReAuthDays: $($SharepointSetting.EmailAttestationReAuthDays)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp7210 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp7210