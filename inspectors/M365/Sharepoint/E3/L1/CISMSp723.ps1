# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh


# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp723
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp723"
        ID               = "7.2.3"
        Title            = "(L1) Ensure external content sharing is restricted"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "ExternalUserAndGuestSharing"
        ExpectedValue    = "ExternalUserSharingOnly or Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Forcing guest authentication ensures that external file sharing is controlled and auditable. Registered guest identities enable the application of restrictions, such as conditional access policies and group memberships, enhancing security."
        Impact           = "When using B2B integration, Entra ID external collaboration settings, such as guest invite settings and collaboration restrictions apply."
        Remediation 	 = 'Set-SPOTenant -SharingCapability ExternalUserSharingOnly'
        References       = @(
            @{ 'Name' = 'Manage Sharing Settings for SharePoint and OneDrive'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off?WT.mc_id=365AdminCSH_spo' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp723
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant | Format-List SharingCapability
			if ($SharepointSetting.SharingCapability -eq "ExternalUserAndGuestSharing")
			{
				$AffectedOptions += "SharingCapability: $($SharepointSetting.SharingCapability)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp723-SPOTenant.txt"
				$endobject = Build-CISMSp723 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp723 -ReturnedValue "SharingCapability: $($SharepointSetting.SharingCapability)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant | Format-List SharingCapability
			if ($SharepointSetting.SharingCapability -eq "ExternalUserAndGuestSharing")
			{
				$AffectedOptions += "SharingCapability: $($SharepointSetting.SharingCapability)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp723-SPOTenant.txt"
				$endobject = Build-CISMSp723-ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp723 -ReturnedValue "SharingCapability: $($SharepointSetting.SharingCapability)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}

	}
	catch
	{
		$endobject = Build-CISMSp723 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp723