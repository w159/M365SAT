# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm859
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm859"
        ID               = "8.5.9"
        Title            = "(L2) Ensure meeting recording is off by default"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "True (On)"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Disabling meeting recordings in the Global meeting policy ensures that only authorized users, such as organizers, co-organizers, and leads, can initiate a recording. This measure helps safeguard sensitive information by preventing unauthorized individuals from capturing and potentially sharing meeting content. Restricting recording capabilities to specific roles allows organizations to exercise greater control over what is recorded, aligning it with the meeting's confidentiality requirements."
        Impact           = "If there are no additional policies allowing anyone to record, then recording will effectively be disabled."
        Remediation      = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowCloudRecording $false'
        References       = @(
            @{ 'Name' = 'Teams settings and policies reference'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/settings-policies-reference?WT.mc_id=TeamsAdminCenterCSH#meeting-engagement" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm859
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowCloudRecording
		
		
		if ($MicrosoftTeamsCheck.AllowCloudRecording -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm859-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm859 -ReturnedValue ($MicrosoftTeamsCheck.AllowCloudRecording) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm859 -ReturnedValue ($MicrosoftTeamsCheck.AllowCloudRecording) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm859 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm859