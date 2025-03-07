# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx321
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx321"
        ID               = "3.2.1"
        Title            = "(L1) Ensure DLP policies are enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Data Loss Prevention (DLP) policies help to protect sensitive data by identifying, monitoring, and automatically protecting it from being shared inappropriately. Without DLP policies, organizations risk accidental data exposure, leading to potential data breaches or compliance violations."
        Impact           = "Enabling a Teams DLP policy will allow sensitive data in Exchange Online and SharePoint Online to be detected or blocked. Always ensure to follow appropriate procedures during testing and implementation of DLP policies based on organizational standards."
        Remediation 	 = 'New-DlpPolicy -Name "Contoso PII" -Template {templatehere}'
        References       = @(
            @{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx321
{
	try
	{
		try
		{
			$dlppolicy = Get-DlpPolicy
			if ([string]::IsNullOrEmpty($dlppolicy))
			{
				$dlppolicy | Format-Table -AutoSize | Out-File "$path\CISMEx321-DLPPolicySettings.txt"
				$endobject = Build-CISMEx321 -ReturnedValue "No DLP Policy Active" -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMEx321 -ReturnedValue "DLP Policy Active" -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
			return $null
		}
		catch
		{
			$endobject = Build-CISMEx321 -ReturnedValue "No DLP Policy Active" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
			return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMEx321 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx321