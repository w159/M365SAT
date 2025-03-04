# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh


# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx613
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx613"
        ID               = "6.1.3"
        Title            = "Mailbox Auditing for E5 Users Is Not Enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling mailbox auditing ensures that Microsoft 365 teams can track unauthorized configuration changes, meet regulatory compliance, and conduct security operations, forensics, or general investigations on mailbox activities. This is especially critical for E5 license users."
        Impact           = "Failure to enable mailbox auditing for E5 users can compromise forensic investigation capabilities, security operations, and regulatory compliance."
        Remediation      = "Use the PowerShell script to enable mailbox auditing and configure necessary audit actions for administrators, delegates, and owners."
        PowerShellScript = '$MBX = Get-EXOMailbox -ResultSize Unlimited | Where-Object {$_.RecipientTypeDetails -eq "UserMailbox" }; $MBX | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner'
        References       = @(
            @{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function VerifyActions { 
	param ( [string]$type, [array]$actions, [array]$auditProperty, [string]$mailboxName) 
	$missingActions = @() 
	$actionCount = 0 
	foreach ($action in $actions) 
	{ 
		if ($auditProperty -notcontains $action) 
		{ 
			$missingActions += "[$mailboxName] Failure: Audit action '$action' missing from $type" 
			$actionCount++ 
		} 
	} if ($actionCount -eq 0) 
	{ 
		return $null
	} 
	else 
	{ 
		return $missingActions
	} 
}

function Audit-CISMEx613
{
	try
	{
		$AdminActions = @( "ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "MailItemsAccessed", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "Send", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules" ) 
		$DelegateActions = @( "ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MailItemsAccessed", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules" ) 
		$OwnerActions = @( "ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MailItemsAccessed", "MoveToDeletedItems", "Send", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules" )
		$violation = @()
		$missingActions = @()
		#$mailboxes = Get-EXOMailbox -PropertySets Audit,Minimum -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" } 
		$mailboxes = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" } 
	foreach ($mailbox in $mailboxes) 
	{ 
		if ($mailbox.AuditEnabled) 
		{ 
		} 
		else 
		{ 
			$violation += $mailbox.UserPrincipalName 
		} 
		$missingActions += VerifyActions -type "AuditAdmin" -actions $AdminActions -auditProperty $mailbox.AuditAdmin -mailboxName $mailbox.UserPrincipalName 
		$missingActions += VerifyActions -type "AuditDelegate" -actions $DelegateActions -auditProperty $mailbox.AuditDelegate -mailboxName $mailbox.UserPrincipalName 
		$missingActions += VerifyActions -type "AuditOwner" -actions $OwnerActions -auditProperty $mailbox.AuditOwner -mailboxName $mailbox.UserPrincipalName 
	}
		if ($violation.Count -igt 0 -or $missingActions.Count -igt 0)
		{
			$violation | Format-Table -AutoSize | Out-File "$path\CISMEx613-MailboxAuditSettingsPerE5User.txt"
			$missingActions | Format-Table -AutoSize | Out-File "$path\CISMEx613-MailboxAuditSettingsPerE5User.txt" -Append
			$endobject = Build-CISMEx613 -ReturnedValue ("file://$path/CISMEx613-MailboxAuditSettingsPerE5User.txt") -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx613 -ReturnedValue "Mailbox Audit for all E5 Mailboxes is enabled" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx613 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx613




