#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5123
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5123"
        ID               = "5.1.2.3"
        Title            = "(L1) Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "AllowedToCreateTenants: True"
        ExpectedValue    = "AllowedToCreateTenants: False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Restricting tenant creation prevents unauthorized or uncontrolled deployment of resources, ensuring organizational control over infrastructure. Allowing non-admin users to create tenants could result in shadow IT, leading to fragmented environments that are hard for IT to manage and secure, potentially causing security vulnerabilities."
        Impact           = "Non-admin users will need to contact I.T. if they have a valid reason to create a tenant."
        Remediation 	 = '$params = @{ AllowedToCreateTenants = $false }; Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions $params'
        References       = @(
            @{ 'Name' = 'Restrict member users default permissions'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5123
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$NonAdminTenants = (Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions | Select-Object AllowedToCreateTenants
		
		# Validation
		if ($NonAdminTenants.AllowedToCreateTenants -ne $False)
		{
			$AffectedOptions += "allowedToCreateTenants: $($NonAdminTenants.AllowedToCreateTenants)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$NonAdminTenants | Format-Table -AutoSize | Out-File "$path\CISMAz5123-AuthorizationDefaultRolePermissions.txt"
			$endobject = Build-CISMAz5123 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5123 -ReturnedValue "allowedToCreateTenants: $($NonAdminTenants.AllowedToCreateTenants)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5123 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5123