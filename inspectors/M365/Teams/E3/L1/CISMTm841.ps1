# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm841
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm841"
        ID               = "8.4.1"
        Title            = "(L1) Ensure app permission policies are configured"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "Microsoft apps: On \n Third-Party apps: On \n Custom apps : On"
        ExpectedValue    = "Microsoft apps: On \n Third-Party apps: Off \n Custom apps : Off"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing users to install third-party or unverified apps poses a potential risk of introducing malicious software to the environment."
        Impact           = "Users will only be able to install approved classes of apps."
        Remediation      = 'https://admin.teams.microsoft.com/policies/manage-apps'
        References       = @(
            @{ 'Name' = 'Use app centric management to manage access to apps'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/app-centric-management" },
            @{ 'Name' = 'Disabling Third-party & custom apps'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/reducing-attack-surface-in-microsoft-teams?view=o365-worldwide#disabling-third-party--custom-apps" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm841
{
	try
	{
        $endobject = Build-CISMTm841 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Return $endobject
	}
	catch
	{
		$endobject = Build-CISMTm841 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm841