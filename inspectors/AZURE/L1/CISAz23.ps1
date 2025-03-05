# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz23
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz23"
        ID               = "2.3"
        Title            = "(L1) Ensure that 'Restrict non-admin users from creating tenants' is set to 'Yes'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "It is recommended to restrict non-admin users from creating new Azure AD or Azure AD B2C tenants. Allowing only administrators to create tenants helps prevent unauthorized users from provisioning new tenants, which could lead to security and compliance risks."
        Impact           = "Enforcing this setting will ensure that only authorized users are able to create new tenants."
        Remediation      = '$RolePermissions = @{}; $RolePermissions["allowedToCreateTenants"] = $False; Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -DefaultUserRolePermissions $RolePermissions'
        References       = @(
            @{ 'Name' = 'What are the default user permissions in Microsoft Entra ID?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions' },
            @{ 'Name' = 'Tenant Creator'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#tenant-creator' },
            @{ 'Name' = 'Disable Microsoft 365 User Tenant Creation in Azure AD'; 'URL' = 'https://blog.admindroid.com/disable-users-creating-new-azure-ad-tenants-in-microsoft-365/' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz23
{
	try
	{
		# Actual Script
		$AuthorizationPolicy = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy")
		
		# Validation
		if ($AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants -eq $true)
		{
			$finalobject = Build-CISAz23 -ReturnedValue ($AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz23 -ReturnedValue (($AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants)) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz23 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz23