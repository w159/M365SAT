# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz226
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz226"
        ID               = "2.2.6"
        Title            = "(L2) Ensure Multi-factor Authentication is Required for Risky Sign-ins"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Requiring Multi-Factor Authentication (MFA) for risky sign-ins enhances security by enforcing additional verification when Microsoft Entra ID detects potentially compromised login attempts."
        Impact           = "Risk Policies for Conditional Access require Microsoft Entra ID P2. Additional overhead to support or maintain these policies may also be required if users lose access to their MFA tokens."
        Remediation      = "Configure a Conditional Access policy in the Microsoft Entra admin portal to enforce MFA for risky sign-ins."
        References       = @(
            @{ 'Name' = 'Common Conditional Access policy: Sign-in risk-based multifactor authentication'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-risk' },
            @{ 'Name' = 'Troubleshooting Conditional Access using the What If tool'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access-what-if' },
            @{ 'Name' = 'Conditional Access insights and reporting'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' },
            @{ 'Name' = 'License requirements'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection#license-requirements' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz226
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.SignInRiskLevels -contains "high") -and ($_.Conditions.SignInRiskLevels -contains "Medium") -and ($_.GrantControls.BuiltInControls -eq "mfa")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for Risky Users!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled')
				{
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy for Risky Users is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz226-MFAPoliciesForAllUsersRisk.txt"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz226 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz226 -ReturnedValue "Conditional Access Policy defining Multi-factor Authentication Policy for Risky Users is enabled!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz226 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz226