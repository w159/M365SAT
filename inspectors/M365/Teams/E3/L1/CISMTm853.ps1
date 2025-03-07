# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm853
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm853"
        ID               = "8.5.3"
        Title            = "(L1) Ensure only people in my org can bypass the lobby"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "People in my org and guests (EveryoneInCompany)"
        ExpectedValue    = "EveryoneInCompanyExcludingGuests"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing all users to bypass the lobby increases the risk of unauthorized access and disruptions during meetings, especially when sensitive information is discussed."
        Impact           = "Individuals who are not part of the organization will have to wait in the lobby until they're admitted by an organizer, co-organizer, or presenter of the meeting. Any individual who dials into the meeting regardless of status will also have to wait in the lobby. This includes internal users who are considered unauthenticated when dialing in."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers "EveryoneInCompanyExcludingGuests"'
        References       = @(
            @{ 'Name' = 'Restricting channel email messages to approved domains'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/step-by-step-guides/reducing-attack-surface-in-microsoft-teams?view=o365-worldwide#restricting-channel-email-messages-to-approved-domains" },
            @{ 'Name' = 'Overview of lobby settings and policies'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-lobby#overview-of-lobby-settings-and-policies" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm853
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AutoAdmittedUsers
		
		
		if ($MicrosoftTeamsCheck.AutoAdmittedUsers -ne "EveryoneInCompanyExcludingGuests")
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm853-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm853 -ReturnedValue ($MicrosoftTeamsCheck.AutoAdmittedUsers) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm853 -ReturnedValue ($MicrosoftTeamsCheck.AutoAdmittedUsers) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm853 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm853