# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm856
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm856"
        ID               = "8.5.6"
        Title            = "(L2) Ensure only organizers and co-organizers can present in meetings"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "Everyone (EveryoneUserOverride)"
        ExpectedValue    = "OrganizerOnlyUserOverride"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Ensuring that only authorized individuals are able to present reduces the risk that a malicious user can inadvertently show content that is not appropriate."
        Impact           = "Only organizers and co-organizers will be able to present without being granted permission."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -DesignatedPresenterRoleMode "OrganizerOnlyUserOverride"'
        References       = @(
            @{ 'Name' = 'Manage who can present and request control in Teams meetings and webinars'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/meeting-who-present-request-control" },
            @{ 'Name' = 'Configure meeting settings (Restrict presenters)'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/reducing-attack-surface-in-microsoft-teams?view=o365-worldwide#configure-meeting-settings-restrict-presenters" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm856
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object DesignatedPresenterRoleMode
		
		
		if ($MicrosoftTeamsCheck.DesignatedPresenterRoleMode -ne "OrganizerOnlyUserOverride")
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm856-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm856 -ReturnedValue ($MicrosoftTeamsCheck.DesignatedPresenterRoleMode) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm856 -ReturnedValue ($MicrosoftTeamsCheck.DesignatedPresenterRoleMode) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm856 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm856