# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx623
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx623"
        ID               = "6.2.3"
        Title            = "(L1) Ensure email from external senders is identified"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Tagging emails from external senders is critical for informing end users of the email origin, helping them identify potential spam or phishing attempts more effectively."
        Impact           = "Mail flow rules using external tagging will need to be disabled before enabling this to avoid duplicate [External] tags"
        Remediation 	 = 'Set-ExternalInOutlook -Enabled $true'
        References       = @(
            @{ 'Name' = 'Native external sender callouts on email in Outlook'; 'URL' = "https://techcommunity.microsoft.com/t5/exchange-team-blog/native-external-sender-callouts-on-email-in-outlook/ba-p/2250098" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx623
{
	try
	{
		$Violation = @()
		$ExternalSenderValidation = Get-ExternalInOutlook
		foreach ($Validation in $ExternalSenderValidation)
		{
			if ($Validation.Enabled -ne $True -or -not [string]::IsNullOrEmpty($Validation.AllowList))
			{
				$Violation += "$($Validation.Identity): $($Validation.Enabled)"
			}
		}
		
		if ($Violation.Count -igt 0)
		{
			$domainwlrules | Format-List | Out-File -FilePath "$path\CISMEx623-ExternalInOutlook.txt"
			$endobject = Build-CISMEx623 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx623 -ReturnedValue "ExternalInOutlook: Enabled" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx623 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx623