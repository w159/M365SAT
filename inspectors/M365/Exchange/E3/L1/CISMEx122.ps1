# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx122
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)

	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMEx122"
		ID				 = "1.2.2"
		Title			 = "(L1) Ensure sign-in to shared mailboxes is blocked"
		ProductFamily    = "Microsoft Exchange"
		DefaultValue	 = "AccountEnabled: True"
		ExpectedValue    = "AccountEnabled: False and 0 Mailboxes"
		ReturnedValue    = $ReturnedValue
		Status			 = $Status
		RiskScore	     = $RiskScore
		RiskRating		 = $RiskRating
		Description	     = "The intent of the shared mailbox is the only allow delegated access from other mailboxes. An admin could reset the password or an attacker could potentially gain access to the shared mailbox allowing the direct sign-in to the shared mailbox and subsequently the sending of email from a sender that does not have a unique identity. To prevent this, block sign-in for the account that is associated with the shared mailbox."
		Impact		     = "There is no actual impact known."
		Remediation 	 = '$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox; $MBX | ForEach { Update-MgUser -UserId $_.ExternalDirectoryObjectId -AccountEnabled $false }'
		References	     = @(@{ 'Name' = 'About Shared Mailboxes'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide" },
			@{ 'Name' = 'Block Sign-In for the Shared Mailbox Account'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide#block-sign-in-for-the-shared-mailbox-account" },
			@{ 'Name' = 'Block Microsoft 365 user accounts with PowerShell'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/block-user-accounts-with-microsoft-365-powershell?view=o365-worldwide#block-individual-user-accounts" })
	}
	return $inspectorobject
}

function Audit-CISMEx122
{
	try
	{
		# Actual Script
		$Count = 0
		$MBX = Get-Mailbox -RecipientTypeDetails SharedMailbox
		foreach ($Account in $MBX)
		{
			$AccountSetting = Get-MgUser -UserId $Account.ExternalDirectoryObjectId
			if ($AccountSetting.AccountEnabled -eq $false -or [string]::IsNullOrEmpty($AccountSetting.AccountEnabled))
			{
				continue
			}
			else
			{
				$Count++
			}
		}
		
		# Validation
		if ($Count -igt 0)
		{
			$MBX | ForEach-Object { Get-MgUser -UserId $_.ExternalDirectoryObjectId } | Format-Table -AutoSize DisplayName, UserPrincipalName, AccountEnabled | Out-File "$path\CISMEx122-SharedMailboxesSignIn.txt"
			$finalobject = Build-CISMEx122 -ReturnedValue $Count -Status "FAIL" -RiskScore "10" -RiskRating "Medium"
			return $finalobject
		}
		else
		{
			$endobject = Build-CISMEx122 -ReturnedValue $Count -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMEx122 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx122