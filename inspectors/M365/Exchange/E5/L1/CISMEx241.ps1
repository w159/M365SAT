# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx241
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx241"
        ID               = "2.4.1"
        Title            = "(L1) Ensure Priority account protection is enabled and configured"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "True"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling priority account protection for users in Microsoft 365 enhances security for accounts with access to sensitive data and high privileges. Priority accounts like CEOs, CISOs, CFOs, and IT admins are frequent targets for spear phishing and whaling attacks. These accounts require stronger security measures to prevent compromise, such as the identification of incidents involving priority accounts and additional built-in custom protections."
        Impact           = "Without priority account protection, high-value accounts are at risk of targeted attacks, potentially leading to data breaches, financial loss, and damage to reputation."
        Remediation		 = 'Set-EmailTenantSettings -EnablePriorityAccountProtection $true'
        References       = @(
            @{ 'Name' = 'Manage and monitor priority accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/setup/priority-accounts?view=o365-worldwide" },
            @{ 'Name' = 'Security recommendations for priority accounts in Microsoft 365'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/priority-accounts-security-recommendations?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx241
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$ExchangeSetting = Get-EmailTenantSettings | Format-List Identity, EnablePriorityAccountProtection
		if ($ExchangeSetting.EnablePriorityAccountProtection -ne $true)
		{
			$AffectedOptions += "EnablePriorityAccountProtection: $($ExchangeSetting.EnablePriorityAccountProtection)"
		}
		
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$ExchangeSetting | Format-Table -AutoSize | Out-File "$path\CISMEx241-EmailTenantSettings.txt"
			$endobject = Build-CISMEx241 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMEx241 -ReturnedValue $("EnablePriorityAccountProtection: $($ExchangeSetting.EnablePriorityAccountProtection)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx241 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx241