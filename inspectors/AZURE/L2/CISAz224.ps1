# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz224
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz224"
        ID               = "2.2.4"
        Title            = "(L1) Ensure Multi-Factor Authentication (MFA) is enabled for Administrative Groups"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Starting October 2024, MFA will be required for all accounts by default."
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enforcing Multi-Factor Authentication (MFA) for administrative groups ensures that only authenticated and authorized personnel can use administrative accounts, reducing the risk of unauthorized access."
        Impact           = "There is an increased cost, as Conditional Access policies require Microsoft Entra ID P1. Similarly, MFA may require additional overhead to maintain. There is also a potential scenario in which the multi-factor authentication method can be lost, and administrative users are no longer able to log in. For this scenario, there should be anemergency access account. Please see References for creating this."
        Remediation      = "Create a Conditional Access policy to enforce Multi-Factor Authentication (MFA) for administrative groups through the Microsoft Entra admin portal."
        References       = @(
            @{ 'Name' = 'Common Conditional Access policy: Require MFA for administrators'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa' },
            @{ 'Name' = 'Manage emergency access accounts in Azure AD'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' },
            @{ 'Name' = 'Troubleshooting Conditional Access using the What If tool'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access-what-if' },
            @{ 'Name' = 'Conditional Access insights and reporting'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting' },
            @{ 'Name' = 'Plan a Conditional Access deployment'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz224
{
	try
	{
		# Actual Script
		$Violation = @()

		#Get all administrative roles
		$Roles = (Get-MgRoleManagementDirectoryRoleDefinition | Where-Object {$_.DisplayName -match "Administrator"}).Id | Sort-Object

		# We use a count check to see if a CA-Policy has all the same amount of Administrator roles to get the correct policy
		$Policies = (Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeRoles.Count -eq $Roles.Count)})

		# In case we have multiple policies:
		foreach ($Policy in $Policies){
			$PolicyRoles = $Policy.Conditions.Users.IncludeRoles | Sort-Object

			# We do a object comparison here as we want to see if all roles are included within the Policy Roles array and output the result as a boolean
			if (($Roles | Compare-Object $PolicyRoles) -as [bool]){
				$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy Exists for Administrative Groups does not contain all administrative groups!"
				($Roles | Compare-Object $PolicyRoles) | Format-Table -AutoSize | Out-File "$path\CISAz224MFAPolicies.txt"
			}
			# We do a check if the full configuration is existing 
			if( -not ($Policy |  Where-Object { ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.GrantControls.BuiltInControls -eq "mfa")})){
				$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy Exists for Administrative Groups is not correctly configured!"
			}
		}

		#We do a regular check for the policy if the policy is existing at all if the first foreach loop is skipped. 
		
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for Administrative Groups"
		}
		else
		{
			#We do a check if the policy is disabled
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy Exists for Administrative Groups is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz224MFAPolicies.txt"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$Violation | Format-Table -AutoSize | Out-File -Append "$path\CISAz224MFAPolicies.txt"
			$finalobject = Build-CISAz224 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "20" -RiskRating "Critical"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz224 -ReturnedValue "Conditional Access Policy defining Multi-factor Authentication Policy Exists for Administrative Groups is enabled!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz224 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz224