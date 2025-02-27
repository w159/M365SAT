# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz222
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz222"
        ID               = "2.2.2"
        Title            = "(L2) Ensure that an exclusionary Geographic Access Policy is considered"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "null"
        ExpectedValue    = "A policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Conditional Access policies can restrict access based on geographic location, preventing unauthorized access from high-risk or unnecessary locations. Implementing a deny list for specific countries reduces exposure to international threats, including APTs."
        Impact           = "Microsoft Entra ID P1 or P2 is required. Limiting access geographically will deny access to users that are traveling or working remotely in a different part of the world. A point-to-site or site to site tunnel such as a VPN is recommended to address exceptions togeographic access policies."
        Remediation      = "Create a Conditional Access policy to block access based on geographic locations via the Microsoft Entra admin portal or PowerShell."
        References       = @(
            @{ 'Name' = 'Conditional Access: Block access by location'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-location' },
            @{ 'Name' = 'What is Conditional Access report-only mode?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz222
{
	try
	{
		# Actual Script
		# Actual Script
		$Violation = @()
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.Locations.IncludeLocations.Count -igt 0) -and ($_.GrantControls.BuiltInControls -eq "block")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Geographic Access!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Geographic Access is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz222GeoAccessPolicies.txt"
				}
			}
		}
		
		# Validation
		if ($affectedpolicy.Count -igt 0)
		{
			$affectedpolicy | Format-Table -AutoSize | Out-File "$path\CISAz222GeoAccessPolicies.txt"
			$finalobject = Build-CISAz222 -ReturnedValue ($affectedpolicy) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz222 -ReturnedValue "Conditional Access Policy defining Geographic Access is enabled!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz222 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz222