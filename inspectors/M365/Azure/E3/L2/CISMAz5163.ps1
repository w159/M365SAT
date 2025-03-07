# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5163
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5163"
        ID               = "5.1.6.3"
        Title            = "(L2) Ensure guest user invitations are limited to the Guest Inviter role"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "everyone"
        ExpectedValue    = "adminsAndGuestInviters or more restrictive"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "By restricting who can invite guest users, organizations reduce the risk of unauthorized accounts being granted access to sensitive resources. Limiting guest invitations ensures that only authorized personnel have the ability to invite external users."
        Impact           = "This introduces an obstacle to collaboration by restricting who can invite guest users to the organization. Designated Guest Inviters must be assigned, and an approval process established and clearly communicated to all users."
        Remediation 	 = 'Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsAndGuestInviters"'
        References       = @(
            @{ 'Name' = 'Configure external collaboration settings for B2B in Microsoft Entra External ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure' },
            @{ 'Name' = 'Microsoft Entra Built-In Role: Guest Inviter'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#guest-inviter' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5163
{
	try
	{
		# Actual Script
		$AuthPolicy = Get-MgPolicyAuthorizationPolicy
		
		
		# Validation
		if ($AuthPolicy.AllowInvitesFrom -eq 'everyone')
		{
			$AuthPolicy | Format-List | Out-File "$path\CISMAz5163-AuthorizationPolicy.txt"
			$endobject = Build-CISMAz5163 -ReturnedValue ($AuthPolicy.AllowInvitesFrom) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5163 -ReturnedValue ($AuthPolicy.AllowInvitesFrom) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5163 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5163