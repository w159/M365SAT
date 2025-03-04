# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx217
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx217"
        ID               = "2.1.7"
        Title            = "(L2) Ensure that an anti-phishing policy has been created"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Anti-Phishing policies are critical for protecting users from phishing attacks, including impersonation and spoofing attempts. These policies use advanced heuristics and safety tips to help identify and mitigate potentially harmful messages."
        Impact           = "Mailboxes that are used for support systems such as helpdesk and billing systems send mail to internal users and are often not suitable candidates for impersonation protection. Care should be taken to ensure that these systems are excluded from Impersonation Protection."
        Remediation      = '$domains = (Get-AcceptedDomain).Name; $params = @{} New-AntiPhishPolicy @params; New-AntiPhishRule -Name "AntiPhish Rule" -AntiPhishPolicy "AntiPhish Policy" -RecipientDomainIs $domains'
        References       = @(
            @{ 'Name' = 'Anti-phishing protection in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-about' },
            @{ 'Name' = 'Configure anti-phishing policies in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-eop-configure' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx217
{
	$AntiPhishPolicyViolation = @()
	$AntiPhishPolicyOK = @()
	Try
	{
		try
		{
			$params = @("name","Enabled","PhishThresholdLevel","EnableTargetedUserProtection","EnableOrganizationDomainsProtection","EnableMailboxIntelligence","EnableMailboxIntelligenceProtection","EnableSpoofIntelligence","TargetedUserProtectionAction","TargetedDomainProtectionAction","MailboxIntelligenceProtectionAction","EnableFirstContactSafetyTips","EnableSimilarUsersSafetyTips","EnableSimilarDomainsSafetyTips","EnableUnusualCharactersSafetyTips","TargetedUsersToProtect","HonorDmarcPolicy")
			$AntiPhishPolicy = Get-AntiPhishPolicy | Format-List $params | Where-Object { $_.IsDefault -eq $true }
			if ($AntiPhishPolicy.count -eq 0)
			{
				$AntiPhishPolicy = Get-AntiPhishPolicy | Format-List $params
			}
			if ($AntiPhishPolicy.enabled -eq $false)
			{
				$AntiPhishPolicyViolation += "Enabled: $($AntiPhishPolicy.enabled)"
			}
			else
			{
				$AntiPhishPolicyOK += "Enabled: $($AntiPhishPolicy.enabled)"
			}
			if ($AntiPhishPolicy.PhishThresholdLevel -ilt 3)
			{
				$AntiPhishPolicyViolation += "PhishThresholdLevel: $($AntiPhishPolicy.PhishThresholdLevel)"
			}
			else
			{
				$AntiPhishPolicyOK += "PhishThresholdLevel: $($AntiPhishPolicy.PhishThresholdLevel)"
			}
			if ($AntiPhishPolicy.EnableTargetedUserProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableTargetedUserProtection: $($AntiPhishPolicy.EnableTargetedUserProtection)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableTargetedUserProtection: $($AntiPhishPolicy.EnableTargetedUserProtection)"
			}
			if ($AntiPhishPolicy.EnableOrganizationDomainsProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableOrganizationDomainsProtection: $($AntiPhishPolicy.EnableOrganizationDomainsProtection)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableOrganizationDomainsProtection: $($AntiPhishPolicy.EnableOrganizationDomainsProtection)"
			}
			if ($AntiPhishPolicy.EnableMailboxIntelligence -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableMailboxIntelligence: $($AntiPhishPolicy.EnableMailboxIntelligence)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableMailboxIntelligence: $($AntiPhishPolicy.EnableMailboxIntelligence)"
			}
			if ($AntiPhishPolicy.EnableMailboxIntelligenceProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableMailboxIntelligenceProtection: $($AntiPhishPolicy.EnableMailboxIntelligenceProtection)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableMailboxIntelligenceProtection: $($AntiPhishPolicy.EnableMailboxIntelligenceProtection)"
			}
			if ($AntiPhishPolicy.EnableSpoofIntelligence -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSpoofIntelligence: $($AntiPhishPolicy.EnableSpoofIntelligence)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableSpoofIntelligence: $($AntiPhishPolicy.EnableSpoofIntelligence)"
			}
			if ($AntiPhishPolicy.TargetedUserProtectionAction -ne 'Quarantine')
			{
				$AntiPhishPolicyViolation += "TargetedUserProtectionAction: $($AntiPhishPolicy.TargetedUserProtectionAction)"
			}
			else
			{
				$AntiPhishPolicyOK += "TargetedUserProtectionAction: $($AntiPhishPolicy.TargetedUserProtectionAction)"
			}
			if ($AntiPhishPolicy.TargetedDomainProtectionAction -ne 'Quarantine')
			{
				$AntiPhishPolicyViolation += "TargetedDomainProtectionAction: $($AntiPhishPolicy.TargetedDomainProtectionAction)"
			}
			else
			{
				$AntiPhishPolicyOK += "TargetedDomainProtectionAction: $($AntiPhishPolicy.TargetedDomainProtectionAction)"
			}
			if ($AntiPhishPolicy.MailboxIntelligenceProtectionAction -ne 'Quarantine')
			{
				$AntiPhishPolicyViolation += "MailboxIntelligenceProtectionAction: $($AntiPhishPolicy.MailboxIntelligenceProtectionAction)"
			}
			else
			{
				$AntiPhishPolicyOK += "MailboxIntelligenceProtectionAction: $($AntiPhishPolicy.MailboxIntelligenceProtectionAction)"
			}
			if ($AntiPhishPolicy.EnableFirstContactSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableFirstContactSafetyTips: $($AntiPhishPolicy.EnableFirstContactSafetyTips)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableFirstContactSafetyTips: $($AntiPhishPolicy.EnableFirstContactSafetyTips)"
			}
			if ($AntiPhishPolicy.EnableSimilarUsersSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSimilarUsersSafetyTips: $($AntiPhishPolicy.EnableSimilarUsersSafetyTips)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableSimilarUsersSafetyTips: $($AntiPhishPolicy.EnableSimilarUsersSafetyTips)"
			}
			if ($AntiPhishPolicy.EnableSimilarDomainsSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSimilarDomainsSafetyTips: $($AntiPhishPolicy.EnableSimilarDomainsSafetyTips)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableSimilarDomainsSafetyTips: $($AntiPhishPolicy.EnableSimilarDomainsSafetyTips)"
			}
			if ($AntiPhishPolicy.EnableUnusualCharactersSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableUnusualCharactersSafetyTips: $($AntiPhishPolicy.EnableUnusualCharactersSafetyTips)"
			}
			else
			{
				$AntiPhishPolicyOK += "EnableUnusualCharactersSafetyTips: $($AntiPhishPolicy.EnableUnusualCharactersSafetyTips)"
			}
			if ($AntiPhishPolicy.TargetedUsersToProtect.count -eq 0)
			{
				$AntiPhishPolicyViolation += "TargetedUsersToProtect: $($AntiPhishPolicy.TargetedUsersToProtect)"
			}
			else
			{
				$AntiPhishPolicyOK += "TargetedUsersToProtect: $($AntiPhishPolicy.TargetedUsersToProtect)"
			}
			if ($AntiPhishPolicy.HonorDmarcPolicy -eq $false)
			{
				$AntiPhishPolicyViolation += "HonorDmarcPolicy: $($AntiPhishPolicy.HonorDmarcPolicy)"
			}
			else
			{
				$AntiPhishPolicyOK += "HonorDmarcPolicy: $($AntiPhishPolicy.HonorDmarcPolicy)"
			}
		}
		catch
		{
			$AntiPhishPolicyViolation += "No AntiPhish Policy Available"
		}
		If ($AntiPhishPolicyViolation.count -igt 0)
		{
			$AntiPhishPolicy | Format-Table -AutoSize | Out-File "$path\CISMEx217-AntiPhishPolicySettings.txt"
			$endobject = Build-CISMEx217 -ReturnedValue $AntiPhishPolicyViolation -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx217 -ReturnedValue $AntiPhishPolicyOK -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
	}
	catch
	{
		$endobject = Build-CISMEx217 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx217


