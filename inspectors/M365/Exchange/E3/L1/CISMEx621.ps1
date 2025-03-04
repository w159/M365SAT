# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx621
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx621"
        ID               = "6.2.1"
        Title            = "(L1) Ensure all forms of mail forwarding are blocked and/or disabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "AllowedOOFType: External <br> AutoForwardEnabled: True"
        ExpectedValue    = "AllowedOOFType: Not External <br> AutoForwardEnabled: False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Attackers or insiders may create mail forwarding rules to exfiltrate sensitive data from the organization. Blocking or disabling such forwarding methods is critical to prevent data leakage."
        Impact           = "Care should be taken before implementation to ensure there is no business need for case-by-case auto-forwarding. Disabling auto-forwarding to remote domains will affect all users and in an organization. Any exclusions should be implemented based on organizational policy."
        Remediation = @'
Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | ft Name, RedirectMessageTo
Remove-TransportRule $_.Name
Get-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode Off
'@
        References       = @(
            @{ 'Name' = 'Procedures for mail flow rules in Exchange Server'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rule-procedures?view=exchserver-2019' },
            @{ 'Name' = 'Control automatic external email forwarding in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding?view=o365-worldwide' },
            @{ 'Name' = 'Automatic email forwarding in Exchange Online'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/all-you-need-to-know-about-automatic-email-forwarding-in/ba-p/2074888' }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx621
{
	try
	{
		$TransportRules = Get-TransportRule | Where-Object { $null -ne $_.RedirectMessageTo } | Select-Object Name, RedirectMessageTo
		$OutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode
		if ($TransportRules.Count -igt 0)
		{
			if ($OutboundSpamFilterPolicy.AutoForwardingMode -eq "Off"){
				$OutboundSpamFilterPolicy | Format-List | Out-File -FilePath "$path\CISMEx621-AffectedTransportRules.txt"
			}
			$TransportRules | Format-List | Out-File -FilePath "$path\CISMEx621-AffectedTransportRules.txt" -Append
			$endobject = Build-CISMEx621 -ReturnedValue ($TransportRules) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx621 -ReturnedValue "No Transport Rules Found!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx621 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx621