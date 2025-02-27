# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2023
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2023"
        ID               = "2.23"
        Title            = "(L1) Ensure That No Custom Subscription Administrator Roles Exist"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "0 (No Custom Roles)"
        ExpectedValue    = "0 (No Custom Roles)"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Classic subscription administrator roles, such as Account Administrator, Service Administrator, and Co-Administrator, provide broad permissions. It is recommended to limit permissions to only what is necessary and avoid custom subscription administrator roles to prevent excessive access."
        Impact           = "Subscriptions will need to be handled by Administrators with permissions."
        Remediation      = "To remove custom subscription administrator roles: Remove-MgRoleManagementDirectoryRoleDefinition -RoleDefinitionId '<Role Definition ID>"
        References       = @(
            @{ 'Name' = 'Add or change Azure subscription administrators'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/add-change-subscription-administrator' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
            @{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
            @{ 'Name' = 'PA-7: Follow just enough administration (least privilege) principle'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz2023
{
	try
	{
		$CustomSubscriptionAdministratorRoleList = @()
		# Actual Script
		$CustomSubscriptionAdministratorRoles = Get-AzRoleDefinition | Where-Object { ($_.IsCustom -eq $true) -and ($_.Actions.contains('*')) }
		
		if ($CustomSubscriptionAdministratorRoles.Count -igt 0)
		{
			foreach ($Role in $CustomSubscriptionAdministratorRoles)
			{
				$CustomSubscriptionAdministratorRoleList += $Role.Name
			}
			$endobject = Build-CISAz2023 -ReturnedValue ($CustomSubscriptionAdministratorRoleList) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2023 -ReturnedValue ($SecureDefaultsState.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2023 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2023