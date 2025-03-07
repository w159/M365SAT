# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx133
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    #Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx133"
        ID               = "1.3.3"
        Title            = "(L2) Ensure 'External sharing' of calendars is not available"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "True and Every Mailbox"
        ExpectedValue    = "False and 0 Mailboxes"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Attackers often spend time learning about organizations before launching an attack. Publicly available calendars can help attackers understand organizational relationships and determine when specific users may be more vulnerable to an attack, such as when they are traveling."
        Impact           = "This functionality is not widely used. As a result, it is unlikely that implementation of this setting will cause an impact to most users. Users that do utilize this functionality are likely to experience a minor inconvenience when scheduling meetings or synchronizing calendars with people outside the tenant."
        Remediation      = '$Policy = Get-SharingPolicy -Identity "Default Sharing Policy"; Set-SharingPolicy -Identity $Policy.Name -Enabled $False'
		References	     = @(@{ 'Name' = 'Share Microsoft 365 calendars with external users'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/manage/share-calendars-with-external-users?view=o365-worldwide" })
    }
    return $inspectorobject
}

function Audit-CISMEx133
{
	try
	{
		# Actual Script
		$ExchangeSetting = Get-SharingPolicy -Identity "Default Sharing Policy"

		
		$affectedmailboxes = @()
		$mailboxes = Get-Mailbox -ResultSize Unlimited
		foreach ($mailbox in $mailboxes)
		{
			# Get the name of the default calendar folder (depends on the mailbox's language) 
			$calendarFolder = [string](Get-MailboxFolderStatistics $mailbox.PrimarySmtpAddress -FolderScope Calendar | Where-Object { $_.FolderType -eq 'Calendar' }).Name
			# Get users calendar folder settings for their default Calendar folder # calendar has the format identity:\<calendar folder name> 
			$calendar = Get-MailboxCalendarFolder -Identity "$($mailbox.PrimarySmtpAddress):\$calendarFolder"
			if ($calendar.PublishEnabled)
			{
				$affectedmailboxes += "Calendar publishing is enabled for $($mailbox.PrimarySmtpAddress) on $($calendar.PublishedCalendarUrl)"
			}
		}
		
		# Validation
		if ($ExchangeSetting.Enabled -eq $true -or $affectedmailboxes.Count -igt 0)
		{
			$affectedmailboxes | Format-Table -AutoSize | Out-File "$path\CISMEx133-CalendarSharingMailboxes.txt"
			$finalobject = Build-CISMEx133 -ReturnedValue $affectedmailboxes.Count -Status "FAIL" -RiskScore "10" -RiskRating "Medium"
			return $finalobject
		}
		else
		{
			$endobject = Build-CISMEx133 -ReturnedValue $affectedmailboxes.Count -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMEx133 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx133