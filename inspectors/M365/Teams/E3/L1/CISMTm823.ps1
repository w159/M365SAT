# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm823
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm823"
        ID               = "8.2.3"
        Title            = "(L1) Ensure external Teams users cannot initiate conversations"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "AllowTeamsConsumerInbound : True"
        ExpectedValue    = "AllowTeamsConsumerInbound : False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing external Teams users to initiate conversations presents a potential security threat as unmanaged users can exploit free or trial Microsoft Teams accounts to engage with organizational users, potentially leading to phishing or unauthorized data access."
        Impact           = "Unrestricted communication from external users increases the risk of social engineering, phishing, and unauthorized interactions."
        Remediation      = 'Set-CsTenantFederationConfiguration -AllowTeamsConsumerInbound $false'
        References       = @(
            @{ 'Name' = 'IT Admins - Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings" },
            @{ 'Name' = 'DarkGate malware delivered via Microsoft Teams - detection and response'; 'URL' = "https://levelblue.com/blogs/security-essentials/darkgate-malware-delivered-via-microsoft-teams-detection-and-response" },
            @{ 'Name' = 'Midnight Blizzard conducts targeted social engineering over Microsoft Teams'; 'URL' = "https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/" },
            @{ 'Name' = 'GIFShell Attack Lets Hackers Create Reverse Shell through Microsoft Teams GIFs'; 'URL' = "https://www.bitdefender.com/en-us/blog/hotforsecurity/gifshell-attack-lets-hackers-create-reverse-shell-through-microsoft-teams-gifs" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm823
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowTeamsConsumerInbound -eq $True)
		{
			$ViolatedTeamsSettings += "AllowTeamsConsumerInbound: True"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalAccess | Format-Table -AutoSize | Out-File "$path\CISMTm823-TeamsTenantFederationConfiguration.txt"
			$endobject = Build-CISMTm823 -ReturnedValue ($ViolatedTeamsSettings) -Status "FAIL" -RiskScore "8" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm823 -ReturnedValue "AllowTeamsConsumerInbound: False" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm823 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm823