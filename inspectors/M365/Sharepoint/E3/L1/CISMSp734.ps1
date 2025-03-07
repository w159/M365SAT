# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp734
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp734"
        ID               = "7.3.4"
        Title            = "(L1) Ensure custom script execution is restricted on site collections"
        ProductFamily    = "Microsoft SharePoint"
		DefaultValue	 = 'DenyAddAndCustomizePages $true or Enabled'
		ExpectedValue    = 'DenyAddAndCustomizePages $true or Enabled'
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing custom script execution on site collections poses a security risk, as such scripts could include malicious code. Organizations lose the ability to enforce governance, limit the scope of inserted code, or block harmful custom scripts."
        Impact           = "Permitting custom scripts can lead to unauthorized deployment of harmful or non-compliant code."
        Remediation	 	 = 'Get-SPOSite | ForEach-Object { Set-SPOSite -Identity $_.Name -DenyAddAndCustomizePages $true }'
        References       = @(
            @{ 'Name' = 'Allow or Prevent Custom Script'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/allow-or-prevent-custom-script' },
            @{ 'Name' = 'Security Considerations of Allowing Custom Scripts'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/security-considerations-of-allowing-custom-script' }
        )
    }
    return $inspectorobject
}

function Audit-CISMSp734
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$SiteViolation = @()
			$Sites = Get-PnPSite | Select-Object Title, Url, DenyAddAndCustomizePages | Where-Object {$_.DenyAddAndCustomizePages -eq "Disabled"}
			foreach ($Site in $Sites)
			{
				$SiteViolation += $Site.Url
			}
			if ($SiteViolation.Count -igt 0)
			{
				$Sites | Format-Table -AutoSize | Out-File "$path\CISMSp734-SPOSite.txt"
				$endobject = Build-CISMSp734 -ReturnedValue ($SiteViolation) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp734 -ReturnedValue "EnableAzureADB2BIntegration: True" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			$SiteViolation = @()
			$Sites = Get-SPOSite | Select-Object Title, Url, DenyAddAndCustomizePages | Where-Object {$_.DenyAddAndCustomizePages -eq "Disabled"}
			foreach ($Site in $Sites)
			{
				$SiteViolation += $Site.Url
			}
			if ($SiteViolation.Count -igt 0)
			{
				$Sites | Format-Table -AutoSize | Out-File "$path\CISMSp734-SPOSite.txt"
				$endobject = Build-CISMSp734 -ReturnedValue ($SiteViolation) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp734 -ReturnedValue "EnableAzureADB2BIntegration: True" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp734 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMSp734