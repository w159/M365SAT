# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm812
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm812"
        ID               = "8.1.2"
        Title            = "(L1) Ensure users can't send emails to a channel emailaddress"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Channel email addresses are not under the tenant's domain and organizations do not have control over the security settings for this email address. An attacker could email channels directly if they discover the channel email address."
        Impact           = "Users will not be able to email the channel directly."
        Remediation      = 'Set-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel $false'
        References       = @(
            @{ 'Name' = 'Restricting channel email messages to approved domains'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/step-by-step-guides/reducing-attack-surface-in-microsoft-teams?view=o365-worldwide#restricting-channel-email-messages-to-approved-domains" },
            @{ 'Name' = 'Send an email to a channel in Microsoft Teams'; 'URL' = "https://support.microsoft.com/en-us/office/send-an-email-to-a-channel-in-microsoft-teams-d91db004-d9d7-4a47-82e6-fb1b16dfd51e" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm812
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowEmailIntoChannel
		
		
		if ($MicrosoftTeamsCheck.AllowEmailIntoChannel -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm812-TeamsClientConfiguration.txt"
			$endobject = Build-CISMTm812 -ReturnedValue ($MicrosoftTeamsCheck.AllowEmailIntoChannel) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm812 -ReturnedValue ($MicrosoftTeamsCheck.AllowEmailIntoChannel) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm812 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm812