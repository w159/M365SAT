# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx654
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx654"
        ID               = "6.5.4"
        Title            = "(L1) Ensure SMTP AUTH is disabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "SmtpClientAuthenticationDisabled : True"
        ExpectedValue    = "SmtpClientAuthenticationDisabled : True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "SMTP AUTH is a legacy protocol that should be disabled to support the principle of least functionality and improve security by blocking older protocols. Modern email clients can connect to Exchange Online without using SMTP AUTH."
        Impact           = "This enforces the default behavior, so no impact is expected unless the organization is using it globally. A per-mailbox setting exists that overrides the tenant-wide setting, allowing an individual mailbox SMTP AUTH capability for special cases."
        Remediation 	 = 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
        References       = @(
            @{ 'Name' = 'Enable or Disable Authenticated Client SMTP Submission (SMTP AUTH) in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx654
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$ExchangeSetting = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
		if ($ExchangeSetting.SmtpClientAuthenticationDisabled -ne $true)
		{
			$AffectedOptions += "SmtpClientAuthenticationDisabled is set to : $($ExchangeSetting.SmtpClientAuthenticationDisabled)"
		}

		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$ExchangeSetting | Format-List | Out-File -FilePath "$path\CISMEx654-OrganizationConfig.txt"
			$endobject = Build-CISMEx654 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx654 -ReturnedValue "SmtpClientAuthenticationDisabled : $($ExchangeSetting.SmtpClientAuthenticationDisabled)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx654 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx654