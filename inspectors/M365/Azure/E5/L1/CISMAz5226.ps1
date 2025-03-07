# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMAz5226
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5226"
        ID               = "5.2.2.6"
        Title            = "(L1) Enable Identity Protection user risk policies"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A correctly configured User Risk Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling an Azure AD Identity Protection user risk policy helps detect and mitigate the risk of compromised user accounts. This policy allows administrators to automatically enforce remediation actions based on the detected risk level, such as requiring password changes or blocking access."
        Impact           = "Upon policy activation, account access will be either blocked or the user will be required to use multi-factor authentication (MFA) and change their password. Users without registered MFA will be denied access, necessitating an admin to recover the account. To avoid inconvenience, it is advised to configure the MFA registration policy for all users under the User Risk policy. Additionally, users identified in the Risky Users section will be affected by this policy. To gain a better understanding of the impact on the organization's environment, the list of Risky Users should be reviewed before enforcing the policy."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'How To: Give risk feedback in Azure AD Identity Protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback' },
            @{ 'Name' = 'What are risk detections?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5226
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and $_.Conditions.UserRiskLevels -eq 'high' -and $_.GrantControls.BuiltInControls -eq 'mfa' -and $_.SessionControls.SignInFrequency.FrequencyInterval -eq 'everyTime'}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5226-UserRiskConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -ne "enabledForReportingButNotEnforced" -or $Policy.State -ne "enabled")
				{
					$Violation += $Policy.Id
				}
			}
		}
		else
		{
			$Violation += "No Conditional Access Policy (Correctly) Configured!"
		}
		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISMAz5226 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5226 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5226 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5226