# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMAz5229
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5229"
        ID               = "5.2.2.9"
        Title            = "(L2) Ensure 'sign-in risk' is blocked for medium and high risk"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Correctly Configured Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling the Azure AD Identity Protection sign-in risk policy ensures that suspicious sign-ins are automatically challenged with multi-factor authentication (MFA). This enhances security by preventing unauthorized access from compromised credentials or unusual locations."
        Impact           = "Sign-in risk is heavily dependent on detecting risk based on atypical behaviors. Due to this it is important to run this policy in a report-only mode to better understand how the organization's environment and user activity may influence sign-in risk before turning the policy on. Once it's understood what actions may trigger a medium or high sign-in risk event I.T. can then work to create an environment to reduce false positives. For example, employees might be required to notify security personnel when they intend to travel with intent to access work resources."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'How To: Give risk feedback in Azure AD Identity Protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5229
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeUsers -eq "All") -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.SignInRiskLevels -contains 'high' -and $_.Conditions.SignInRiskLevels -contains 'medium') -and $_.GrantControls.BuiltInControls -eq "block"}
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5229-SignInRiskConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -eq "disabled")
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
			$endobject = Build-CISMAz5229 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5229 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5229 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5229