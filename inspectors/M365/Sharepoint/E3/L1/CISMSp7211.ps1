# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp7211
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp7211"
        ID               = "7.2.11"
        Title            = "(L1) Ensure the SharePoint default sharing link permission is set"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "Edit"
        ExpectedValue    = "View"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Setting the default sharing link permission to 'View' ensures that users must consciously select 'Edit' when granting permissions. This minimizes the risk of unintentionally providing edit access to resources and upholds the principle of least privilege."
        Impact           = "The default 'Edit' permission could result in accidental overexposure of sensitive documents, increasing the risk of data modification or leaks."
        Remediation 	 = 'Set-SPOTenant -DefaultLinkPermission View'
        References       = @(
            @{ 'Name' = 'File and folder links'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off#file-and-folder-links' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp7211
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant
			if ($SharepointSetting.DefaultLinkPermission -ne "View")
			{
				$AffectedOptions += "DefaultLinkPermission: $($SharepointSetting.DefaultLinkPermission)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7211-SPOTenant.txt"
				$endobject = Build-CISMSp7211 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp7211 -ReturnedValue "DefaultLinkPermission: $($SharepointSetting.DefaultLinkPermission)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant
			if ($SharepointSetting.DefaultLinkPermission -ne $True)
			{
				$AffectedOptions += "DefaultLinkPermission: $($SharepointSetting.DefaultLinkPermission)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7211-SPOTenant.txt"
				$endobject = Build-CISMSp7211 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp7211 -ReturnedValue "DefaultLinkPermission: $($SharepointSetting.DefaultLinkPermission)" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp7211 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp7211