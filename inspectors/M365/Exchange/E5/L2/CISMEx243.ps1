# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx243
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx243"
        ID               = "2.4.3"
        Title            = "(L2) Ensure Microsoft Defender for Cloud Apps is enabled and configured"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "By default, presets are not applied to any users or groups."
        ExpectedValue    = "All presets are applied to any users or groups."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Security teams can receive notifications of triggered alerts for atypical or suspicious activities, see how the organization's data in Microsoft 365 is accessed and used, suspend user accounts exhibiting suspicious activity, and require users to log back in to Microsoft 365 apps after an alert has been triggered"
        Impact           = "Strict policies are more likely to cause false positives in anti-spam, phishing, impersonation, spoofing and intelligence responses."
        Remediation 	 = 'https://security.microsoft.com/cloudapps/settings'
        References       = @(
            @{ 'Name' = 'Connect Microsoft 365 to Microsoft Defender for Cloud Apps'; 'URL' = "https://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-365#connect-microsoft-365-to-microsoft-defender-for-cloud-apps" },
            @{ 'Name' = 'Connect Azure to Microsoft Defender for Cloud Apps'; 'URL' = "https://learn.microsoft.com/en-us/defender-cloud-apps/protect-azure#connect-azure-to-microsoft-defender-for-cloud-apps" },
            @{ 'Name' = 'Best practices for protecting your organization with Defender for Cloud Apps'; 'URL' = "https://learn.microsoft.com/en-us/defender-cloud-apps/best-practices" },
            @{ 'Name' = 'Get started with Microsoft Defender for Cloud Apps'; 'URL' = "https://learn.microsoft.com/en-us/defender-cloud-apps/get-started" },
            @{ 'Name' = 'What are risk detections?'; 'URL' = "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx243
{
	try
	{
		# This inspector cannot be automated due to not everyone having Microsoft 365 Defender for Cloud Apps enabled
		# Validation
		$endobject = Build-CISMEx243 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Return $endobject

		return $null
	}
	catch
	{
		$endobject = Build-CISMEx243 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx243