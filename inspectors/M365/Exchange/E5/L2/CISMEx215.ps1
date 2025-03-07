# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx215
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx215"
        ID               = "2.1.5"
        Title            = "(L2) Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "Undefined"
        ExpectedValue    = "EnableATPForSPOTeamsODB: True EnableSafeDocs: True AllowSafeDocsOpen: False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is designed to protect against sharing malicious files within the organization. When an infected file is detected, it is blocked until the security team intervenes, helping to prevent the spread of malware."
        Impact           = "Impact associated with Safe Attachments is minimal, and equivalent to impact associated with anti-virus scanners in an environment."
        Remediation      = 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -AllowSafeDocsOpen $false'
        References       = @(
            @{ 'Name' = 'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-odfb-teams-about' }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx215
{
	$AffectedSettings = @()
	$CorrectSettings = @()
	try
	{
		# Actual Script
		try
		{
			$Policies = Get-AtpPolicyForO365 | Format-List Name, EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen
			
			if ($Settings.EnableATPForSPOTeamsODB -eq $False)
			{
				$AffectedSettings += "$($Policies.Name): EnableATPForSPOTeamsODB: $($Settings.EnableATPForSPOTeamsODB)"
			}
			else
			{
				$CorrectSettings += "$($Policies.Name): EnableATPForSPOTeamsODB: $($Settings.EnableATPForSPOTeamsODB)"
			}
			if ($Settings.EnableSafeDocks -eq $False)
			{
				$AffectedSettings += "$($Policies.Name): EnableSafeDocks: $($Settings.EnableSafeDocks)"
			}
			else
			{
				$CorrectSettings += "$($Policies.Name): EnableSafeDocks: $($Settings.EnableSafeDocks)"
			}
			if ($Settings.AllowSafeDocsOpen -ne $False)
			{
				$AffectedSettings += "$($Policies.Name): AllowSafeDocsOpen: $($Settings.AllowSafeDocsOpen)"
			}
			else
			{
				$CorrectSettings += "$($Policies.Name): AllowSafeDocsOpen: $($Settings.AllowSafeDocsOpen)"
			}
			
		}
		catch
		{
			$endobject = Build-CISMEx215 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
			return $endobject
		}
		
		# Validation
		if ($AffectedSettings.Count -igt 0)
		{
			$endobject = Build-CISMEx215 -ReturnedValue $AffectedSettings -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx215 -ReturnedValue $CorrectSettings -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx215 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx215