# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx242
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx242"
        ID               = "2.4.2"
        Title            = "Ensure Priority accounts have 'Strict protection' presets applied"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "By default, presets are not applied to any users or groups."
        ExpectedValue    = "All presets are applied to any users or groups."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling priority account protection for users in Microsoft 365 enhances security for accounts with access to sensitive data and high privileges. Priority accounts like CEOs, CISOs, CFOs, and IT admins are frequent targets for spear phishing and whaling attacks. These accounts require stronger protection to prevent compromise, such as the identification of incidents involving priority accounts and additional built-in custom protections."
        Impact           = "Strict policies are more likely to cause false positives in anti-spam, phishing, impersonation, spoofing and intelligence responses."
        Remediation 	 = 'Enable-EOPProtectionPolicyRule -Identity "Strict Preset Security Policy"; Enable-ATPProtectionPolicyRule -Identity "Strict Preset Security Policy"'
        References       = @(
            @{ 'Name' = 'Preset security policies in EOP and Microsoft Defender for Office 365'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide" },
            @{ 'Name' = 'Recommended settings for EOP and Microsoft Defender for Office 365 security'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365?view=o365-worldwide#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365" },
            @{ 'Name' = 'Security recommendations for priority accounts in Microsoft 365'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/priority-accounts-security-recommendations?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx242
{
	# https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide
	
	
	
	try
	{
		# Actual Script
		$AffectedOptions = @()
		#AntiPhishPolicy (AntiPhishing)
		try
		{
			$Policy1 = AntiPhishPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy1))
			{
				$AffectedOptions += "No Strict AntiPhishPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict AntiPhishPolicy Available"
		}
		#MalwareFilterPolicy (Anti-Malware)
		try
		{
			$Policy2 = MalwareFilterPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy2))
			{
				$AffectedOptions += "No Strict MalwareFilterPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict MalwareFilterPolicy Available"
		}
		#HostedContentFilterPolicy (Anti-Spam)
		try
		{
			$Policy3 = HostedContentFilterPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy3))
			{
				$AffectedOptions += "No Strict HostedContentFilterPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict HostedContentFilterPolicy Available"
		}
		#SafeAttachmentPolicy (SafeAttachments)
		try
		{
			$Policy4 = SafeAttachmentPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy4))
			{
				$AffectedOptions += "No Strict SafeAttachmentPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict SafeAttachmentPolicy Available"
		}
		#SafeLinksPolicy (SafeLinks)
		try
		{
			$Policy5 = SafeLinksPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy5))
			{
				$AffectedOptions += "No Strict SafeLinksPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict SafeLinksPolicy Available"
		}
		#EOPProtectionPolicyRule
		try
		{
			$Policy6 = Get-EOPProtectionPolicyRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
			if ([string]::IsNullOrEmpty($Policy5))
			{
				$AffectedOptions += "No Strict EOPProtectionPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict EOPProtectionPolicy Available"
		}
		#ATPProtectionPolicyRule
		try
		{
			$Policy7 = Get-ATPProtectionPolicyRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
			if ([string]::IsNullOrEmpty($Policy5))
			{
				$AffectedOptions += "No Strict ATPProtectionPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict ATPProtectionPolicy Available"
		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMEx242-StrictPolicySettings.txt"
			$endobject = Build-CISMEx242 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx242 -ReturnedValue "All presets are applied to any users or groups." -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx242 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx242