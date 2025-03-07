# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm857
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm857"
        ID               = "8.5.7"
        Title            = "(L1) Ensure external participants can't give or request control"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "False (Off)"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Ensuring that only authorized individuals and not external participants are able to present and request control reduces the risk that a malicious user can inadvertently show content that is not appropriate."
        Impact           = "External participants will not be able to present or request control during the meeting."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalParticipantGiveRequestControl $false'
        References       = @(
            @{ 'Name' = 'Manage who can present and request control in Teams meetings'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/meeting-who-present-request-control" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm857
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl
		
		
		if ($MicrosoftTeamsCheck.AllowExternalParticipantGiveRequestControl -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm857-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm857 -ReturnedValue ($MicrosoftTeamsCheck.AllowExternalParticipantGiveRequestControl) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm857 -ReturnedValue ($MicrosoftTeamsCheck.AllowExternalParticipantGiveRequestControl) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm857 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm857