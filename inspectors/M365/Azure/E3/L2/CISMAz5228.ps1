# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5228
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5228"
        ID               = "5.2.2.8"
        Title            = "(L2) Ensure admin center access is limited to administrative roles"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No - Non-administrators can access Microsoft Admin Portals."
        ExpectedValue    = "Yes - Only Administrators can access Microsoft Admin Portals."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Restricting admin center access to administrative roles ensures that privileged actions can only be performed by authorized users. This minimizes the risk of unauthorized access and helps maintain the integrity and security of critical administrative operations."
        Impact           = "PIM functionality will be impacted unless non-privileged users are first assigned to a permanent group or role that is excluded from this policy. When attempting to checkout a role in the Entra ID PIM area they will receive the message 'You don't have access to this Your sign-in was successful but you don't have permission to access this resource.'"
        Remediation  	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
        References       = @(
            @{ 'Name' = 'Conditional Access: Microsoft Admin Portals'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#microsoft-admin-portals' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5228
{
	try
	{
		# Actual Script
		$Violation = @()
		$DirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition
		$PrivilegedRoles = ($DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}).TemplateId


		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {((-not ($PrivilegedRoles | Compare-Object $_.Conditions.Users.ExcludeRoles) -as [bool]) -eq $true) -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "MicrosoftAdminPortals") -and $_.GrantControls.BuiltInControls -eq "block"}
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*administrative*" }
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5228-AdministrativeConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -eq "disabled")
				{
					$Violation += $Policy.Id
				}
				else
				{
					#Multiple Checks to determine if the policy is not configured correctly
					$PolicyInfo = Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.Id)"
					if ([string]::IsNullOrEmpty($PolicyInfo.conditions.userRiskLevels) -or -not [string]::IsNullOrEmpty($PolicyInfo.conditions.signInRiskLevels))
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.conditions.applications.includeApplications -ne "All" -or $PolicyInfo.conditions.users.includeUsers -ne "All")
					{
						$Violation += $Policy.Id
					}
				}
				
			}
		}
		else
		{
			$Violation += "Could not verify is policy exists!"
		}
		# Validation
		if ($Violation.Count -ne 0)
		{
			$endobject = Build-CISMAz5228 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5228 -ReturnedValue "Conditional Access Policy is Correctly Configured!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5228 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5228