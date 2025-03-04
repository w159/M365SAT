# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx244
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx244"
        ID               = "2.4.4"
        Title            = "(L1) Ensure Zero-hour auto purge for Microsoft Teams is on"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "True"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Zero-hour auto purge (ZAP) is designed to protect users who have received zero-day malware messages or malicious content. ZAP works by continually monitoring spam and malware signatures and taking retroactive actions on messages that have already been delivered, helping to mitigate threats from weaponized content delivered to users."
        Impact           = "As with any anti-malware or anti-phishing product, false positives may occur."
        Remediation 	 = 'Set-TeamsProtectionPolicy -Identity "Teams Protection Policy" -ZapEnabled $true'
        References       = @(
            @{ 'Name' = 'Configure ZAP for Teams protection in Defender for Office 365 Plan 2'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/mdo-support-teams-about?view=o365-worldwide#configure-zap-for-teams-protection-in-defender-for-office-365-plan-2" },
            @{ 'Name' = 'Zero-hour auto purge (ZAP) in Microsoft Teams'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge?view=o365-worldwide#zero-hour-auto-purge-zap-in-microsoft-teams" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx244
{		
	try
	{
		# Actual Script
		$AffectedOptions = @()
		
		try{
			$TPP = Get-TeamsProtectionPolicy
			if ($TPP.ZapEnabled -ne $true){
				$AffectedOptions += "ZapEnabled: $($TPP.ZapEnabled)"
			}
			$TPR = Get-TeamsProtectionPolicyRule | Select-Object ExpectIf
			if (-not [string]::IsNullOrEmpty($TPR.ExpectIf)){
				$AffectedOptions += "ZapEnabled: $($TPR.ZapEnabled)"
			}
		}catch{
		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMEx244-ZAPTEAMSExchange.txt"
			$endobject = Build-CISMEx244 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx244 -ReturnedValue $("Policy-ZapEnabled: $($TPP.ZapEnabled) Rule-ZapEnabled: $($TPR.ZapEnabled)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx244 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx244