# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx652
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx652"
        ID               = "6.5.2"
        Title            = "(L1) Ensure MailTips are enabled for end users (Automated)"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "MailTipsAllTipsEnabled: False <br/> MailTipsExternalRecipientsTipsEnabled: False <br/> MailTipsGroupMetricsEnabled: False <br/> MailTipsLargeAudienceThreshold: 25"
        ExpectedValue    = "MailTipsAllTipsEnabled: True <br/> MailTipsExternalRecipientsTipsEnabled: True <br/> MailTipsGroupMetricsEnabled: True <br/> MailTipsLargeAudienceThreshold: >25"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "MailTips help users identify potentially dangerous email patterns, such as sending messages to large groups or external recipients. Disabling this feature exposes users to the risk of inadvertently sending sensitive information or performing malicious activities."
        Impact           = "Risk of accidental information leakage or malicious activity without user awareness."
        Remediation	 	 = 'Set-OrganizationConfig -MailTipsAllTipsEnabled $true -MailTipsExternalRecipientsTipsEnabled $true -MailTipsGroupMetricsEnabled $true -MailTipsLargeAudienceThreshold "25"'
        References       = @(
            @{ 'Name' = 'MailTips in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/mailtips/mailtips" },
            @{ 'Name' = 'Set-OrganizationConfig'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/exchange/set-organizationconfig?view=exchange-ps" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx652
{
	try
	{
		$ExchangeMailTipsData = @()
		Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled, MailTipsLargeAudienceThreshold
		if ($ExchangeMailTips.MailTipsAllTipsEnabled -match 'False')
		{
			$ExchangeMailTipsData += "MailTipsAllTipsEnabled: $($ExchangeMailTips.MailTipsAllTipsEnabled)"
		}
		if ($ExchangeMailTips.MailTipsExternalRecipientsTipsEnabled -match 'False')
		{
			$ExchangeMailTipsData += "MailTipsExternalRecipientsTipsEnabled: $($ExchangeMailTips.MailTipsExternalRecipientsTipsEnabled)"
		}
		if ($ExchangeMailTips.MailTipsGroupMetricsEnabled -match 'False')
		{
			$ExchangeMailTipsData += "MailTipsGroupMetricsEnabled: $($ExchangeMailTips.MailTipsGroupMetricsEnabled)"
		}
		if ($ExchangeMailTips.MailTipsLargeAudienceThreshold -ne 25)
		{
			$ExchangeMailTipsData += "MailTipsLargeAudienceThreshold: $($ExchangeMailTips.MailTipsLargeAudienceThreshold)"
		}
		if ($ExchangeMailTipsData.count -igt 0)
		{
			$ExchangeMailTipsData | Format-List | Out-File -FilePath "$path\CISMEx652-MailTipsConfiguration.txt"
			$endobject = Build-CISMEx652 -ReturnedValue $ExchangeMailTipsData -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx652 -ReturnedValue "All MailTips Settings are Enabled" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx652 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx652