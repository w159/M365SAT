# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that an exclusionary Device code flow policy is considered
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz223
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz223"
        ID               = "2.2.3"
        Title            = "(L2) Ensure that an exclusionary Device code flow policy is considered"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Policy"
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Conditional Access policies should be used to restrict the Device Code authentication flow. This flow is typically used for devices with limited input capability, such as IoT devices. It should be restricted to only users who require it for administrative tasks, such as using Azure PowerShell."
        Impact           = "This policy should be tested using the Report-only mode before implementation. Without a full and careful understanding of the accounts and personnel who require Device code authentication flow, implementing this policy can block authentication for users and devices who rely on Device code flow. For users and devices that rely on device code flow authentication, more secure alternatives should be implemented wherever possible."
        Remediation      = "Create a Conditional Access policy to restrict Device Code Flow authentication through the Microsoft Entra admin portal."
        References       = @(
            @{ 'Name' = 'Device code flow'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows#device-code-flow' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-7-restrict-resource-access-based-on--conditions' },
            @{ 'Name' = 'What is Conditional Access report-only mode?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only' },
            @{ 'Name' = 'Block authentication flows with Conditional Access policy'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-authentication-flows' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz223
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.AuthenticationFlows.TransferMethods -eq "deviceCodeFlow") -and ($_.GrantControls.BuiltInControls -eq "block")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Device code flow!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Device code flow is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz223-DeviceCodeFlowPolicy.txt"
				}
			}
		}
		
		# Validation

		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz223 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz223 -ReturnedValue "Conditional Access Policy defining Device code flow is enabled!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz223 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz223