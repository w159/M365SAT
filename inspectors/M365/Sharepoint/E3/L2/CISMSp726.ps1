# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp726
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMSp726"
        ID               = "7.2.6"
        Title            = "(L2) Ensure SharePoint external sharing is managed through domain whitelist/blacklists"
        ProductFamily    = "Microsoft SharePoint"
        DefaultValue     = "Limit external sharing by domain is unchecked \n SharingDomainRestrictionMode: None \n SharingDomainRestrictionMode: <Undefined>"
        ExpectedValue    = "SharingDomainRestrictionMode: AllowList"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Restricting external sharing by domain reduces the risk of sensitive information being exposed to unauthorized entities. Attackers may attempt to leverage unrestricted sharing to access critical data."
        Impact           = "Enabling this feature will prevent users from sharing documents with domains outside of the organization unless allowed."
        Remediation 	 = 'Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList "domain1.com domain2.com"'
        References       = @(
            @{ 'Name' = 'Restrict Sharing of SharePoint and OneDrive Content by Domain'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/restricted-domains-sharing' }
        )
    }
    return $inspectorobject
}


function Audit-CISMSp726
{
	Try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$ShareSettings = (Get-PnPTenant).SharingDomainRestrictionMode
			If ($ShareSettings -ne "AllowList")
			{
				$message = "SharingDomainRestrictionMode is set to $($ShareSettings)."
				$ShareSettings | Format-Table -AutoSize | Out-File "$path\CISMSp726-SPOTenant.txt"
				$endobject = Build-CISMSp726 -ReturnedValue ($message) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp726 -ReturnedValue "SharingDomainRestrictionMode is set to $($ShareSettings)." -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		else
		{
			$ShareSettings = (Get-SPOTenant).SharingDomainRestrictionMode
			If ($ShareSettings -ne "AllowList")
			{
				$message = "SharingDomainRestrictionMode is set to $($ShareSettings)."
				$ShareSettings | Format-Table -AutoSize | Out-File "$path\CISMSp726-SPOTenant.txt"
				$endobject = Build-CISMSp726 -ReturnedValue ($message) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMSp726 -ReturnedValue "SharingDomainRestrictionMode is set to $($ShareSettings)." -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
	}
	catch
	{
		$endobject = Build-CISMSp726 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Audit-CISMSp726


