# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm824
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm824"
        ID               = "8.2.4"
        Title            = "(L1) Ensure communication with Skype users is disabled"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "AllowPublicUsers : True"
        ExpectedValue    = "AllowPublicUsers : False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Skype was deprecated on July 31, 2021. Allowing communication with Skype users increases the organization's attack surface and poses security risks. Disabling this functionality minimizes potential vulnerabilities. Exceptions may be considered for partner organizations or satellite offices still using Skype."
        Impact           = "Teams users will be unable to communicate with Skype users that are not in the same organization."
        Remediation      = 'Set-CsTenantFederationConfiguration -AllowPublicUsers $false'
        References       = @(
            @{ 'Name' = 'IT Admins - Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm824
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowPublicUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowPublicUsers: True"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalAccess | Format-Table -AutoSize | Out-File "$path\CISMTm824-TeamsTenantFederationConfiguration.txt"
			$endobject = Build-CISMTm824 -ReturnedValue ($ViolatedTeamsSettings) -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm824 -ReturnedValue "AllowPublicUsers: False" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm824 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm824