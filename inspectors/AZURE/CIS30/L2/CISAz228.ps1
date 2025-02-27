# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose:  Ensure Multifactor Authentication is Required to access Microsoft Admin Portals
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz228
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz228"
        ID               = "2.2.8"
        Title            = "(L1) Ensure Multi-Factor Authentication (MFA) is enabled for Microsoft Admin Portals"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling Multi-Factor Authentication (MFA) for administrative portals helps mitigate the risk of unauthorized access by adding an additional layer of authentication for administrators accessing sensitive settings."
        Impact           = "Conditional Access policies require Microsoft Entra ID P1 or P2 licenses. Similarly, they may require additional overhead to maintain if users lose access to their MFA. Any users or groups which are granted an exception to this policy should be carefully tracked, be granted only minimal necessary privileges, and conditional access exceptions should be reviewed or investigated."
        Remediation      = "Create a Conditional Access Policy to enable MFA for admin portals by enforcing MFA when accessing Microsoft admin portals."
        References       = @(
            @{ 'Name' = 'Conditional Access: Users, groups, and workload identities'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups' },
            @{ 'Name' = 'Common Conditional Access policy: Require multifactor authentication for admins accessing Microsoft admin portals'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-mfa-admin-portals' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' }
        )
    }
    return $inspectorobject
}
#15high

function Audit-CISAz228
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "MicrosoftAdminPortals") -and ($_.GrantControls.BuiltInControls -eq "mfa")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for Microsoft Admin Portals!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled')
				{
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy for Microsoft Admin Portals is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz228-MFAPoliciesForMicrosoftAdminPortals.txt"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz228 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz228 -ReturnedValue "Conditional Access Policy defining Multi-factor Authentication Policy for Microsoft Admin Portals is enabled!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz228 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz228