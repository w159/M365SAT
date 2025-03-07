# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2114
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx2114"
        ID               = "2.1.14"
        Title            = "(L1) Ensure inbound anti-spam policies do not contain allowed domains"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "AllowedSenderDomains : {}"
        ExpectedValue    = "AllowedSenderDomains : {}"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allow-listing email addresses or domains without additional verification such as mail flow rules bypasses essential spam filtering and sender authentication (SPF, DKIM, DMARC). This creates a high risk of attackers successfully delivering malicious emails to the inbox, including malware and phishing emails that would otherwise be filtered."
        Impact           = "This is the default behavior. Allowed domains may reduce false positives, however, this benefit is outweighed by the importance of having a policy which scans all messages regardless of the origin. As an alternative consider sender based lists. This supports the principle of zero trust."
        Remediation 	 = 'Set-HostedContentFilterPolicy -Identity Default -AllowedSenderDomains @{}; $AllowedDomains = Get-HostedContentFilterPolicy | Where-Object {$_.AllowedSenderDomains}; $AllowedDomains | Set-HostedContentFilterPolicy -AllowedSenderDomains @{}'
        References       = @(
            @{ 'Name' = 'Allow and block lists in anti-spam policies'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/anti-spam-protection-about#allow-and-block-lists-in-anti-spam-policies" }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx2114
{	
	Try
	{
		$HostedConnectionFilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default
		
		If ([string]::IsNullOrEmpty($HostedConnectionFilterPolicy.AllowedSenderDomains) -or $HostedConnectionFilterPolicy.AllowedSenderDomains -ne "{}")
		{
			$HostedConnectionFilterPolicy | Format-Table -AutoSize | Out-File "$path\CISMEx2114-HostedConnectionFilterPolicy.txt"
			$endobject = Build-CISMEx2114 -ReturnedValue $HostedConnectionFilterPolicy -Status "FAIL" -RiskScore "9" -RiskRating "Medium"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx2114 -ReturnedValue $HostedConnectionFilterPolicy -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx2114 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx2114


