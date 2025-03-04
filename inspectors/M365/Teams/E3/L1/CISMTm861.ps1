# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm861
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMTm861"
        ID               = "8.6.1"
        Title            = "(L1) Ensure users can report security concerns in Teams"
        ProductFamily    = "Microsoft Teams"
        DefaultValue     = "True \n Report message destination: Microsoft Only"
        ExpectedValue    = "True \n Report message destination: Designated email address"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Users will be able to more quickly and systematically alert administrators of suspicious malicious messages within Teams. The content of these messages may be sensitive in nature and therefore should be kept within the organization and not shared with Microsoft without first consulting company policy."
        Impact           = "Enabling message reporting has an impact beyond just addressing security concerns. When users of the platform report a message, the content could include messages that are threatening or harassing in nature, possibly stemming from colleagues. Due to this the security staff responsible for reviewing and acting on these reports should be equipped with the skills to discern and appropriately direct such messages to the relevant departments, such as Human Resources (HR)."
        Remediation      = 'Set-CsTeamsMessagingPolicy -Identity Global -AllowSecurityEndUserReporting $true; $usersub = "example@contoso.com"; $params = @{ Identity = "DefaultReportSubmissionPolicy" EnableReportToMicrosoft = $false ReportChatMessageEnabled = $false ReportChatMessageToCustomizedAddressEnabled = $true ReportJunkToCustomizedAddress = $true ReportNotJunkToCustomizedAddress = $true ReportPhishToCustomizedAddress = $true ReportJunkAddresses = $usersub ReportNotJunkAddresses = $usersub ReportPhishAddresses = $usersub }; Set-ReportSubmissionPolicy @params; New-ReportSubmissionRule -Name DefaultReportSubmissionRule -ReportSubmissionPolicy DefaultReportSubmissionPolicy -SentTo $usersub'
        References       = @(
            @{ 'Name' = 'User reported message settings in Microsoft Teams'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/submissions-teams?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMTm861
{
	try
	{
		$ViolatedTeamsSettings = @()
		$CorrectTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMessagingPolicy -Identity Global | Select-Object AllowSecurityEndUserReporting
		$MicrosoftReportPolicy = Get-ReportSubmissionPolicy | Select-Object ReportJunkToCustomizedAddress, ReportNotJunkToCustomizedAddress, ReportPhishToCustomizedAddress, ReportJunkAddresses, ReportNotJunkAddresses, ReportPhishAddresses, ReportChatMessageEnabled, ReportChatMessageToCustomizedAddressEnabled
		if ($MicrosoftTeamsCheck.AllowSecurityEndUserReporting -eq $False)
		{
			$ViolatedTeamsSettings += "AllowSecurityEndUserReporting: $($MicrosoftTeamsCheck.AllowSecurityEndUserReporting)"
		}
		else
		{
			$CorrectTeamsSettings += "AllowSecurityEndUserReporting: $($MicrosoftTeamsCheck.AllowSecurityEndUserReporting)"
		}
		if ($MicrosoftReportPolicy.ReportJunkToCustomizedAddress -eq $False)
		{
			$ViolatedTeamsSettings += "ReportJunkToCustomizedAddress: $($MicrosoftReportPolicy.ReportJunkToCustomizedAddress)"
		}
		else
		{
			$CorrectTeamsSettings += "ReportJunkToCustomizedAddress: $($MicrosoftReportPolicy.ReportJunkToCustomizedAddress)"
		}
		if ($MicrosoftReportPolicy.ReportNotJunkToCustomizedAddress -eq $False)
		{
			$ViolatedTeamsSettings += "ReportNotJunkToCustomizedAddress: $($MicrosoftReportPolicy.ReportNotJunkToCustomizedAddress)"
		}
		else
		{
			$CorrectTeamsSettings += "ReportNotJunkToCustomizedAddress: $($MicrosoftReportPolicy.ReportNotJunkToCustomizedAddress)"
		}
		if ($MicrosoftReportPolicy.ReportPhishToCustomizedAddress -eq $False)
		{
			$ViolatedTeamsSettings += "ReportPhishToCustomizedAddress: $($MicrosoftReportPolicy.ReportPhishToCustomizedAddress)"
		}
		else
		{
			$CorrectTeamsSettings += "ReportPhishToCustomizedAddress: $($MicrosoftReportPolicy.ReportPhishToCustomizedAddress)"
		}
		if ([string]::IsNullOrEmpty($MicrosoftReportPolicy.ReportJunkAddresses))
		{
			$ViolatedTeamsSettings += "ReportJunkAddresses: NULL"
		}
		else
		{
			$CorrectTeamsSettings += "ReportJunkAddresses: $($MicrosoftReportPolicy.ReportJunkAddresses)"
		}
		if ([string]::IsNullOrEmpty($MicrosoftReportPolicy.ReportNotJunkAddresses))
		{
			$ViolatedTeamsSettings += "ReportNotJunkAddresses: NULL"
		}
		else
		{
			$CorrectTeamsSettings += "ReportNotJunkAddresses: $($MicrosoftReportPolicy.ReportJunkAddresses)"
		}
		if ([string]::IsNullOrEmpty($MicrosoftReportPolicy.ReportPhishAddresses))
		{
			$ViolatedTeamsSettings += "ReportPhishAddresses: NULL"
		}
		else
		{
			$CorrectTeamsSettings += "ReportPhishAddresses: $($MicrosoftReportPolicy.ReportPhishAddresses)"
		}
		if ($MicrosoftReportPolicy.ReportChatMessageEnabled -eq $True)
		{
			$ViolatedTeamsSettings += "ReportChatMessageEnabled: $($MicrosoftReportPolicy.ReportChatMessageEnabled)"
		}
		else
		{
			$CorrectTeamsSettings += "ReportChatMessageEnabled: $($MicrosoftReportPolicy.ReportChatMessageEnabled)"
		}
		if ($MicrosoftReportPolicy.ReportChatMessageToCustomizedAddressEnabled -eq $False)
		{
			$ViolatedTeamsSettings += "ReportChatMessageToCustomizedAddressEnabled: $($MicrosoftReportPolicy.ReportChatMessageToCustomizedAddressEnabled)"
		}
		else
		{
			$CorrectTeamsSettings += "ReportChatMessageToCustomizedAddressEnabled: $($MicrosoftReportPolicy.ReportChatMessageToCustomizedAddressEnabled)"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$ViolatedTeamsSettings | Format-Table -AutoSize | Out-File "$path\CISMTm811-TeamsMessagingSubmissionPolicy.txt"
			$endobject = Build-CISMTm861 -ReturnedValue ($ViolatedTeamsSettings) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMTm861 -ReturnedValue ($CorrectTeamsSettings) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMTm861 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMTm861