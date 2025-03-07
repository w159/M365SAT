# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx651
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx651"
        ID               = "6.5.1"
        Title            = "(L1) Ensure modern authentication for Exchange Online is enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "True"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Disabling Modern Authentication allows legacy authentication protocols, which can be exploited to bypass strong authentication mechanisms like multifactor authentication. Enabling Modern Authentication ensures secure connections between email clients and Exchange Online."
        Impact           = "Users of older email clients, such as Outlook 2013 and Outlook 2016, will no longer be able to authenticate to Exchange using Basic Authentication, which will necessitate migration to modern authentication practices."
        Remediation 	 = 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $True'
        References       = @(
            @{ 'Name' = 'Enable or disable modern authentication in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx651
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$ExchangeSetting = Get-OrganizationConfig | Select-Object Name, OAuth2ClientProfileEnabled
		ForEach ($Organization in $ExchangeSetting)
		{
			if ($ExchangeSetting.OAuth2ClientProfileEnabled -ne $true)
			{
				$AffectedOptions += "$($ExchangeSetting.Name): OAuth2ClientProfileEnabled is: $($ExchangeSetting.OAuth2ClientProfileEnabled)"
			}
		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$ExchangeSetting | Format-List | Out-File -FilePath "$path\CISMEx651-OrganizationConfig.txt"
			$endobject = Build-CISMEx651 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx651 -ReturnedValue "OAuth2ClientProfileEnabled: $($ExchangeSetting.OAuth2ClientProfileEnabled)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx651 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx651