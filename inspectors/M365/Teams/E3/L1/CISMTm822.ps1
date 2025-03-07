# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm822
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm822"
        ID               = "8.2.2"
        Title            = "(L1) Ensure communication with unmanaged Teams users is disabled"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "AllowTeamsConsumer : True"
        ExpectedValue    = "AllowTeamsConsumer : False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing users to communicate with unmanaged Teams users presents a potential security threat as little effort is required by threat actors to gain access to a trial or free Microsoft Teams account."
        Impact           = "Users will be unable to communicate with Teams users who are not managed by an organization."
        Remediation      = 'Set-CsTenantFederationConfiguration -AllowTeamsConsumer $false'
        References       = @(
            @{ 'Name' = 'IT Admins - Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings" },
            @{ 'Name' = 'DarkGate malware delivered via Microsoft Teams - detection and response'; 'URL' = "https://levelblue.com/blogs/security-essentials/darkgate-malware-delivered-via-microsoft-teams-detection-and-response" },
            @{ 'Name' = 'Midnight Blizzard conducts targeted social engineering over Microsoft Teams'; 'URL' = "https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/" },
            @{ 'Name' = 'GIFShell Attack Lets Hackers Create Reverse Shell through Microsoft Teams GIFs'; 'URL' = "https://www.bitdefender.com/en-us/blog/hotforsecurity/gifshell-attack-lets-hackers-create-reverse-shell-through-microsoft-teams-gifs" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm822
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowTeamsConsumer -eq $True)
		{
			$ViolatedTeamsSettings += "AllowTeamsConsumer: $($TeamsExternalAccess.AllowTeamsConsumer)"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalAccess | Format-Table -AutoSize | Out-File "$path\CISMTm822-TeamsTenantFederationConfiguration.txt"
			$endobject = Build-CISMTm822 -ReturnedValue ($ViolatedTeamsSettings) -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm822 -ReturnedValue "AllowTeamsConsumer: False" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm822 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm822