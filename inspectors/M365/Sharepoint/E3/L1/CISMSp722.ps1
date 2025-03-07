# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp722
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp722"
        ID               = "7.2.2"
        Title            = "(L1) Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling Azure AD B2B integration ensures that external users with guest accounts are subject to Azure AD access policies such as multifactor authentication. Without this integration, files can be shared without adequate auditing or identity controls, increasing security risks."
        Impact           = "B2B collaboration is used with other Entra services so should not be new or unusual. Microsoft also has made the experience seamless when turning on integration on SharePoint sites that already have active files shared with guest users. The referenced Microsoft article on the subject has more details on this."
        Remediation	 	 = 'Set-SPOTenant -EnableAzureADB2BIntegration $true'
        References       = @(
            @{ 'Name' = 'SharePoint and OneDrive Integration with Microsoft Entra B2B'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/sharepoint-azureb2b-integration#enabling-the-integration' },
            @{ 'Name' = 'B2B Collaboration Overview'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp722
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant | Format-Table EnableAzureADB2BIntegration
			if ($SharepointSetting.EnableAzureADB2BIntegration -ne $True)
			{
				$AffectedOptions += "EnableAzureADB2BIntegration: False"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp722-SPOTenant.txt"
				$endobject = Build-CISMSp722 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp722 -ReturnedValue "EnableAzureADB2BIntegration: True" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant | Format-Table EnableAzureADB2BIntegration
			if ($SharepointSetting.EnableAzureADB2BIntegration -ne $True)
			{
				$AffectedOptions += "EnableAzureADB2BIntegration: False"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp722-SPOTenant.txt"
				$endobject = Build-CISMSp722 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp722 -ReturnedValue "EnableAzureADB2BIntegration: True" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp722 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp722