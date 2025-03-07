# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm852
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm852"
        ID               = "8.5.2"
        Title            = "(L1) Ensure anonymous users and dial-in callers cannot start a meeting"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "False (Off)"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Not allowing anonymous participants to automatically start a meeting reduces the risk of unauthorized access and meeting spamming."
        Impact           = "Anonymous participants will not be able to start a Microsoft Teams meeting."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToStartMeeting $false'
        References       = @(
            @{ 'Name' = 'Manage anonymous participant access to Teams meetings, webinars, and town halls (IT admins)'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/anonymous-users-in-meetings" },
            @{ 'Name' = 'Overview of lobby settings and policies'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/who-can-bypass-meeting-lobby#overview-of-lobby-settings-and-policies" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm852
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting
		
		
		if ($MicrosoftTeamsCheck.AllowAnonymousUsersToStartMeeting -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm852-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm852 -ReturnedValue ($MicrosoftTeamsCheck.AllowAnonymousUsersToStartMeeting) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm852 -ReturnedValue ($MicrosoftTeamsCheck.AllowAnonymousUsersToStartMeeting) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm852 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm852