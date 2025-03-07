# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5234
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5234"
        ID               = "5.2.3.4"
        Title            = "(L1) Ensure all member users are 'MFA capable'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "IsMFACapable: false if there is no CA policy enforcing MFA"
        ExpectedValue    = "IsMFACapable: true"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Multifactor authentication (MFA) requires an individual to present a minimum of two separate forms of authentication before access is granted. Users who are not MFA capable have never registered a strong authentication method for MFA that complies with policy, and may not be using MFA. This could be the result of having never signed in, exclusion from a Conditional Access (CA) policy requiring MFA, or a missing CA policy entirely. Identifying these users can highlight policy lapses and help ensure compliance."
        Impact           = "When using the UI audit method guest users will appear in the report and unless the organization is applying MFA rules to guests then they will need to be manually filtered. Accounts that provide on-premises directory synchronization also appear in these reports."
        Remediation  	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails/fromNav/Identity'
        References       = @(
            @{ 'Name' = 'View applied Conditional Access policies in Microsoft Entra sign-in logs'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-applied-conditional-access-policies' },
            @{ 'Name' = 'Authentication Methods Activity'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5234
{
	try
	{	
		$Check = Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "IsMfaCapable eq false and UserType eq 'Member'" | Select-Object UserPrincipalName, IsMfaCapable,IsAdmin


		if ($Check.Count -igt 0)
		{
			$Check | Format-Table -AutoSize | Out-File "$path\CISMAz5234-NotCapableMFAUsers.txt"
			$endobject = Build-CISMAz5234 -ReturnedValue ("file://$path\CISMAz5234-NotCapableMFAUsers.txt") -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5234 -ReturnedValue "All Settings are Enabled and correctly configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5234 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

return Audit-CISMAz5234