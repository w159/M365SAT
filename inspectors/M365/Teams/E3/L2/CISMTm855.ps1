# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm855
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm855"
        ID               = "8.5.5"
        Title            = "(L2) Ensure meeting chat does not allow anonymous users"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "On for everyone (Enabled)"
        ExpectedValue    = "EnabledExceptAnonymous"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Ensuring that only authorized individuals can read and write chat messages during a meeting reduces the risk that a malicious user can inadvertently show content that is not appropriate or view sensitive information."
        Impact           = "Only authorized individuals will be able to read and write chat messages during a meeting."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -MeetingChatEnabledType "EnabledExceptAnonymous"'
        References       = @(
            @{ 'Name' = 'Set-CsTeamsMeetingPolicy'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/skype/set-csteamsmeetingpolicy?view=skype-ps#-meetingchatenabledtype" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm855
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object MeetingChatEnabledType
		
		
		if ($MicrosoftTeamsCheck.MeetingChatEnabledType -ne "EnabledExceptAnonymous")
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm855-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm855 -ReturnedValue ($MicrosoftTeamsCheck.MeetingChatEnabledType) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm855 -ReturnedValue ($MicrosoftTeamsCheck.MeetingChatEnabledType) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm855 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm855