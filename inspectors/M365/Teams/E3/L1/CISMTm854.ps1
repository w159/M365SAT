# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm854
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm854"
        ID               = "8.5.4"
        Title            = "(L1) Ensure that users dialing in cannot bypass the lobby"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "False (Off)"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing dial-in users to bypass the lobby increases the risk of unauthorized access to sensitive meetings. The organizer should have control over who joins."
        Impact           = "Individuals who are dialing in to the meeting must wait in the lobby until a meeting organizer, co-organizer, or presenter admits them."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowPSTNUsersToBypassLobby $false'
        References       = @(
            @{ 'Name' = 'Choose who can bypass the lobby in meetings hosted by your organization'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/who-can-bypass-meeting-lobby?WT.mc_id=TeamsAdminCenterCSH#choose-who-can-bypass-the-lobby-in-meetings-hosted-by-your-organization" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm854
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby
		
		
		if ($MicrosoftTeamsCheck.AllowPSTNUsersToBypassLobby -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm854-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm854 -ReturnedValue ($MicrosoftTeamsCheck.AllowPSTNUsersToBypassLobby) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm854 -ReturnedValue ($MicrosoftTeamsCheck.AllowPSTNUsersToBypassLobby) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm854 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm854