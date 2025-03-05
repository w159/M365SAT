# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2024
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2024"
        ID               = "2.24"
        Title            = "(L2) Ensure a Custom Role is Assigned Permissions for Administering Resource Locks"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "0 (No Custom Role Assigned)"
        ExpectedValue    = "1 (Custom Role Assigned)"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Resource locks provide an additional layer of protection for critical Azure resources by preventing unintended deletions or modifications. Since resource lock management operates outside of standard Role-Based Access Control (RBAC), it is recommended to create and assign a dedicated role for managing resource locks to ensure only authorized personnel can make changes."
        Impact           = "By adding this role, specific permissions may be granted for managing just resource locks rather than needing to provide the wide Owner or User Access Administrator role, reducing the risk of the user being able to do unintentional damage."
        Remediation      = 'To create and assign a custom role for administering resource locks use the following command: $role = @{ Name = "Resource Lock Administrator" Description = "Allows management of resource locks" Actions = @("Microsoft.Authorization/locks/*") NotActions = @() AssignableScopes = @("/subscriptions/<subscriptionId>") }; New-AzRoleDefinition -Role $role'
        References       = @(
            @{ 'Name' = 'Azure custom roles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles' },
            @{ 'Name' = 'Quickstart: Check access for a user to Azure resources'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
            @{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
            @{ 'Name' = 'PA-7: Follow just enough administration (least privilege) principle'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle' }
        )
    }
    return $inspectorobject
}

#5medium

function Audit-CISAz2024
{
	try
	{
		$ResourceLockAdministratorsList = @()
		# Actual Script
		$ResourceLockAdministrators = Get-AzRoleDefinition | Where-Object { ($_.IsCustom -eq $true) -and ($_.Name -like '*Resource Lock*') }
		
		if ($ResourceLockAdministrators.Count -igt 0)
		{
			foreach ($Role in $ResourceLockAdministrators)
			{
				$ResourceLockAdministratorsList += $Role.Name
			}
			$endobject = Build-CISAz2024 -ReturnedValue ($ResourceLockAdministratorsList) -Status "FAIL" -RiskScore "4" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2024 -ReturnedValue ($ResourceLockAdministrators) -Status "PASS" -RiskScore "5" -RiskRating "Medium"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2024 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2024