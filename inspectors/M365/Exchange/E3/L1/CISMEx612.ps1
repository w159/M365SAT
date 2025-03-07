# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx612
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx612"
        ID               = "6.1.2"
        Title            = "(L1) Ensure mailbox auditing for E3 users is Enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling mailbox auditing ensures that Microsoft 365 teams can track unauthorized configuration changes, meet regulatory compliance, and conduct security operations, forensics, or general investigations on mailbox activities. This is especially critical for E3 license users."
        Impact           = "Failure to enable mailbox auditing for E3 users can result in the inability to trace unauthorized mailbox activities, reducing the effectiveness of forensic investigations and compliance efforts."
        Remediation 	 = 'Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner'
        References       = @(
            @{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" }
        )
    }
    return $inspectorobject
}

function Audit-CISMEx612
{
	try
	{
		# Short Script
		# $MailAudit = Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited | Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner
		$MailAudit = Get-Mailbox -ResultSize Unlimited | Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner
		$MailboxAuditData = @()
		$MailboxAudit1 = $MailAudit | Where-Object { $_.AuditEnabled -eq $false }
		if ($MailboxAudit1 -ne $null)
		{
			foreach ($Mailbox in $MailboxAudit1)
			{
				$MailboxAuditData += "AuditDisabled: $($Mailbox.Name)"
			}
			if ($MailboxAuditData.Count -igt 0)
			{
				$MailAudit | Format-Table -AutoSize | Out-File "$path\CISMEx612-MailboxAuditSettingsPerUser.txt"
				$endobject = Build-CISMEx612 -ReturnedValue ($MailboxAuditData) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
				return $endobject
			}
			else
			{
				$endobject = Build-CISMEx612 -ReturnedValue ("AuditDisabled: False") -Status "PASS" -RiskScore "0" -RiskRating "None"
				Return $endobject
			}
		}
		$endobject = Build-CISMEx612 -ReturnedValue ("AuditDisabled: False") -Status "PASS" -RiskScore "0" -RiskRating "None"
		Return $endobject
		
	}
	catch
	{
		$endobject = Build-CISMEx612 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMEx612
