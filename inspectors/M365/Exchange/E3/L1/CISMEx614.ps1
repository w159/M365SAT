# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx614
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx614"
        ID               = "6.1.4"
        Title            = "(L1) Ensure 'AuditBypassEnabled' is not enabled on mailboxes"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "0 (All False)"
        ExpectedValue    = "0 (All False)"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "If a mailbox has 'AuditBypassEnabled', it allows access without generating audit logs, which can conceal malicious activity. Ensuring that this setting is disabled is crucial for comprehensive incident response and forensics."
        Impact           = "Malicious insiders or attackers could bypass audit logging, concealing unauthorized actions such as data theft or tampering."
        Remediation 	 = '$MBXAudit = Get-MailboxAuditBypassAssociation -ResultSize unlimited | Where-Object { $_.AuditBypassEnabled -eq $true }; foreach ($mailbox in $MBXAudit) { $mailboxName = $mailbox.Name; Set-MailboxAuditBypassAssociation -Identity $mailboxName -AuditBypassEnabled $false }'
        References       = @(
            @{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx614
{
	try
	{
		$MBX = Get-MailboxAuditBypassAssociation -ResultSize unlimited
		$AuditBypassCheck = $MBX | Where-Object { $_.AuditBypassEnabled -eq $true } | Format-Table Name, AuditBypassEnabled
		if ($AuditBypassCheck.Count -igt 0)
		{
			$MBX | Format-Table -AutoSize | Out-File "$path\CISMEx614-MailboxAuditBypassAssociation.txt"
			$endobject = Build-CISMEx614 -ReturnedValue ($AuditBypassCheck.Count) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx614 -ReturnedValue "AuditBypassEnabled is Disabled for all mailboxes" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMEx614 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx614
