# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2014
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2014"
        ID               = "2.14"
        Title            = "(L1) Ensure That 'Users Can Register Applications' Is Set to 'No'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Allowing users to register applications can lead to security risks if not properly controlled. Limiting application registration to administrators or pre-approved roles ensures that applications undergo a formal security review and approval process, reducing the potential for malicious applications to access sensitive data."
        Impact           = "Enforcing this setting will create additional requests for approval that will need to be addressed by an administrator. If permissions are delegated, a user may approve a malevolent third party application, potentially giving it access to your data."
        Remediation      = 'Use the PowerShell script to restrict application registration. Execute the following to disable user application registration: Import-Module Microsoft.Graph.Identity.SignIns; $params = @{AllowedToCreateApps = $false}; Update-MgPolicyAuthorizationPolicy -BodyParameter $params'
        References       = @(
            @{ 'Name' = 'Restrict who can create applications'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-app-roles#restrict-who-can-create-applications' },
            @{ 'Name' = 'Who has permission to add applications to my Azure AD instance?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-added#who-has-permission-to-add-applications-to-my-azure-ad-instance' },
            @{ 'Name' = 'GS-1: Align organization roles, responsibilities and accountabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-1-define-asset-management-and-data-protection-strategy' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-protect-and-limit-highly-privileged-users' },
            @{ 'Name' = 'Managing user consent for applications using Office 365 APIs'; 'URL' = 'https://learn.microsoft.com/en-us/archive/blogs/exchangedev/managing-user-consent-for-applications-using-office-365-apis' },
            @{ 'Name' = 'Admin Consent for Permissions in Azure Active Directory'; 'URL' = 'https://nicksnettravels.builttoroam.com/post-2017-01-24-admin-consent-for-permissions-in-azure-active-directory-aspx/' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz2014
{
	try
	{
		# Actual Script
		$Policy = Get-MgPolicyAuthorizationPolicy
		
		# Validation
		if ($Policy.DefaultUserRolePermissions.AllowedToCreateApps -eq $true)
		{
			$endobject = Build-CISAz2014 -ReturnedValue ($Policy.DefaultUserRolePermissions.AllowedToCreateApps) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2014 -ReturnedValue ($Policy.DefaultUserRolePermissions.AllowedToCreateApps) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2014 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2014