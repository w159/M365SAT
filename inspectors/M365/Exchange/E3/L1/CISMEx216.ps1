# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx216
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx216"
        ID               = "2.1.6"
        Title            = "(L1) Ensure Exchange Online Spam Policies are set to notify administrators"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "BccSuspiciousOutboundMail: False / NotifyOutboundSpam: False"
        ExpectedValue    = "BccSuspiciousOutboundMail: True / NotifyOutboundSpam: True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling notifications for administrators when spam is detected from a user's account helps quickly identify and mitigate potential breaches. A blocked account is a strong indicator of a compromised user being used to send spam emails."
        Impact           = "Notification of users that have been blocked should not cause an impact to the user."
        Remediation      = '$BccEmailAddress = @(""); $NotifyEmailAddress = @(""); Set-HostedOutboundSpamFilterPolicy -Identity Default -BccSuspiciousOutboundAdditionalRecipients $BccEmailAddress -BccSuspiciousOutboundMail $true -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyEmailAddress'
        References       = @(
            @{ 'Name' = 'Outbound spam protection in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-protection-about' }
        )
    }
    return $inspectorobject
}


function Inspect-CISMEx216
{
	Try
	{
		$spamfilterviolation = @()
		$spamfilterpolicy = Get-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, Notify*
		if ($spamfilterpolicy.BccSuspiciousOutboundMail -eq $false)
		{
			$spamfilterviolation += "BccSuspiciousOutboundMail: $($spamfilterpolicy.BccSuspiciousOutboundMail)"
		}
		if ($spamfilterpolicy.NotifyOutboundSpam -eq $false)
		{
			$spamfilterviolation += "NotifyOutboundSpam: $($spamfilterpolicy.NotifyOutboundSpam)"
		}
		If ($spamfilterviolation.count -igt 0)
		{
			$spamfilterpolicy | Format-List | Out-File "$path\CISMEx216-AntiSpamPolicySettings.txt"
			$endobject = Build-CISMEx216 -ReturnedValue $spamfilterviolation -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx216 -ReturnedValue $("BccSuspiciousOutboundMail: $($spamfilterpolicy.BccSuspiciousOutboundMail) NotifyOutboundSpam: $($spamfilterpolicy.NotifyOutboundSpam)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
	}
	catch
	{
		$endobject = Build-CISMEx216 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx216


