#Requires -module Az.Accounts
# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2013
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz2013"
        ID               = "2.13"
        Title            = "(L2) Ensure 'User consent for applications' is set to 'Do not allow user consent' or 'Allow for Verified Publishers'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Allow user consent for apps"
        ExpectedValue    = "Do not allow user consent OR Allow user consent for apps from verified publishers, for selected permissions"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "If Microsoft Entra ID is running as an identity provider for third-party applications, permissions and consent should be restricted to administrators or pre-approved applications. Allowing broad user consent can expose the organization to malicious applications attempting to exfiltrate data or abuse privileged accounts."
        Impact           = "Enforcing this setting may create additional requests that administrators need to review."
        Remediation      = 'Disable user consent in the Azure Portal via `https://portal.azure.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings` or use the following PowerShell command: Import-Module Microsoft.Graph.Identity.SignIns; $params = @{DefaultUserRolePermissions = @{PermissionGrantPoliciesAssigned = @()}}; Update-MgPolicyAuthorizationPolicy -BodyParameter $params'
        References       = @(
            @{ 'Name' = 'Configure how users consent to applications'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?pivots=portal#configure-user-consent-to-applications' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-protect-and-limit-highly-privileged-users' },
            @{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
            @{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz2013
{
	try
	{
		$AffectedOptions = @()
		
		Import-Module Microsoft.Graph.Identity.DirectoryManagement
		# Old Variant
		$UserConsent = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
		
		
		if ($userConsent.defaultUserRolePermissions.permissionGrantPoliciesAssigned -contains "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
		{
			$endobject = Build-CISAz2013 -ReturnedValue ($userConsent.defaultUserRolePermissions.permissionGrantPoliciesAssigned) -Status "FAIL" -RiskScore "12" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz2013 -ReturnedValue ($userConsent.defaultUserRolePermissions.permissionGrantPoliciesAssigned) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz2013 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz2013