# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx213
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMEx213"
        ID               = "2.1.3"
        Title            = "(L1) Ensure notifications for internal users sending malware is Enabled"
        ProductFamily    = "Microsoft Exchange"
        DefaultValue     = "EnableInternalSenderAdminNotifications: False \n InternalSenderAdminAddress: Null"
        ExpectedValue    = "True, with a configured mailbox or distribution list address"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling notifications for internal users sending malware is crucial for early detection of compromised accounts or devices within an organization. This setting alerts administrators if an internal user sends a message that contains malware."
        Impact           = "Notification of account with potential issues should not have an impact on the user."
        Remediation      = 'Set-MalwareFilterPolicy -Identity "Malware Filter Policy Name" -Action DeleteMessage -EnableInternalSenderAdminNotifications $true -InternalSenderAdminAddress "admin@yourdomain.com"'
        References       = @(
            @{ 'Name' = 'Anti-malware Protection in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about' },
            @{ 'Name' = 'Configure Anti-malware Policies in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure' }
        )
    }
    return $inspectorobject
}

function Inspect-CISMEx213
{
	Try
	{
		$findings = @()
		$MalwareFilterPolicy = Get-MalwareFilterPolicy | Select-Object Identity, EnableInternalSenderAdminNotifications, InternalSenderAdminAddress
		
		foreach ($Policy in $MalwareFilterPolicy)
		{
			if ($Policy.EnableInternalSenderAdminNotifications -eq $false -or [String]::IsNullOrEmpty($Policy.InternalSenderAdminAddress))
			{
				$findings += "$($Policy.Identity): has EnableInternalSenderAdminNotifications on False and $($Policy.InternalSenderAdminAddress) as addresses"
			}
			
		}
		
		If ($findings.Count -igt 0)
		{
			$MalwareFilterPolicy | Format-Table -AutoSize | Out-File "$path\CISMEx213-MalwareSenderNotificationsPolicySettings.txt"
			$endobject = Build-CISMEx213 -ReturnedValue $findings -Status "FAIL" -RiskScore "12" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMEx213 -ReturnedValue $("$($Policy.Identity): has EnableInternalSenderAdminNotifications on True and $($Policy.InternalSenderAdminAddress) as addresses") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
		
	}
	catch
	{
		$endobject = Build-CISMEx213 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Inspect-CISMEx213


