# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz24
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz24"
        ID               = "2.4"
        Title            = "(L1) Ensure Guest Users Are Reviewed on a Regular Basis"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No guests"
        ExpectedValue    = "No unnecessary guests"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Guest users are typically added outside your employee onboarding/offboarding process and could potentially be overlooked indefinitely. To mitigate security risks, guest users should be reviewed on a regular basis to ensure they are still required. Additionally, guest users should not have administrative privileges unless absolutely necessary."
        Impact           = "Before removing guest users, determine their use and scope. Like removing any user, there may be unforeseen consequences to systems if an account is removed without careful consideration"
        Remediation      = '$GuestUsers = Get-MgUser -Filter "UserType eq "Guest"; ForEach-Object {Remove-MgUser -UserId $_.UserPrincipalName}'
        References       = @(
            @{ 'Name' = 'Properties of an Azure Active Directory B2B collaboration user'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/user-properties' },
            @{ 'Name' = 'Delete a user'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/add-users#delete-a-user' },
            @{ 'Name' = 'PA-4: Review and reconcile user access regularly'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-4-review-and-reconcile-user-access-regularly' },
            @{ 'Name' = 'Microsoft Entra Plans & Pricing'; 'URL' = 'https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing' },
            @{ 'Name' = 'How To: Manage inactive user accounts'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' },
            @{ 'Name' = 'Restore or remove a recently deleted user'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-restore' }
        )
    }
    return $inspectorobject
}
function Audit-CISAz24
{
	try
	{
		# Actual Script
		$GuestUserList = @()
		$GuestUsers = Get-MgUser -Filter "UserType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, UserType -Unique
		
		# Validation
		foreach ($GuestUser in $GuestUsers)
		{
			$GuestUserList += "$($GuestUser.DisplayName): $($GuestUser.UserPrincipalName)"
		}
		
		if ($GuestUserList.Count -igt 0)
		{
			$GuestUsers | Format-Table -AutoSize | Out-File "$path\CISAz140GuestUserReport.txt"
			$endobject = Build-CISAz24 -ReturnedValue ($GuestUserList.Count) -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz24 -ReturnedValue ($GuestUserList.Count) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz24 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz24