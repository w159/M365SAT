# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm851
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm851"
        ID               = "8.5.1"
        Title            = "(L2) Ensure anonymous users cannot join meetings"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing anonymous users to join Teams meetings poses a security risk, especially for meetings containing sensitive information. This setting can also allow unauthorized individuals to misuse the meeting link for unscheduled meetings."
        Impact           = "Individuals who were not sent or forwarded a meeting invite will not be able to join the meeting automatically."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting $false'
        References       = @(
            @{ 'Name' = 'Configure Teams meetings with protection for sensitive data'; 'URL' = "https://learn.microsoft.com/en-us/MicrosoftTeams/configure-meetings-sensitive-protection" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm851
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting
		
		
		if ($MicrosoftTeamsCheck.AllowAnonymousUsersToJoinMeeting -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm851-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm851 -ReturnedValue ($MicrosoftTeamsCheck.AllowAnonymousUsersToJoinMeeting) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm851 -ReturnedValue ($MicrosoftTeamsCheck.AllowAnonymousUsersToJoinMeeting) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm851 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm851