# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm858
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm858"
        ID               = "8.5.8"
        Title            = "(L2) Ensure external meeting chat is off"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "True (On)"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "This meeting policy setting controls whether users can read or write messages in external meeting chats with untrusted organizations. If an external organization is on the list of trusted organizations, this setting will be ignored. Restricting access to chat in meetings hosted by external organizations limits the opportunity for an exploit like GIFShell or DarkGate malware from being delivered to users."
        Impact           = "When joining external meetings users will be unable to read or write chat messages in Teams meetings with organizations that they don't have a trust relationship with. This will completely remove the chat functionality in meetings. From an I.T. perspective both the upkeep of adding new organizations to the trusted list and the decision-making process behind whether to trust or not trust an external partner will increase time expenditure."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalNonTrustedMeetingChat $false'
        References       = @(
            @{ 'Name' = 'Teams settings and policies reference'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/settings-policies-reference?WT.mc_id=TeamsAdminCenterCSH#meeting-engagement" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm858
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalNonTrustedMeetingChat
		
		
		if ($MicrosoftTeamsCheck.AllowExternalNonTrustedMeetingChat -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm858-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm858 -ReturnedValue ($MicrosoftTeamsCheck.AllowExternalNonTrustedMeetingChat) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm858 -ReturnedValue ($MicrosoftTeamsCheck.AllowExternalNonTrustedMeetingChat) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm858 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm858