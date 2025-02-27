# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31011
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31011"
        ID               = "3.1.11"
        Title            = "(L1) Ensure that Microsoft Cloud Security Benchmark policies are not set to 'Disabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = ">0"
        ExpectedValue    = "0"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A security policy defines the desired configuration of resources in your environment and helps ensure compliance with company or regulatory security requirements. The MCSB Policy Initiative provides a set of security recommendations based on best practices and is associated with every subscription by default. When a policy 'Effect' is set to Audit, policies in the MCSB ensure that Defender for Cloud evaluates relevant resources for supported recommendations. To ensure that policies within the MCSB are not being missed when the Policy Initiative is evaluated, none of the policies should have an Effect of 'Disabled'."
        Impact           = "Policies within the MCSB default to an effect of Audit and will evaluate - but not enforce - policy recommendations. Ensuring these policies are set to Audit simply ensures that the evaluation occurs to allow administrators to understand where an improvement may be possible. Administrators will need to determine if the recommendations are relevant and desirable for their environment, then manually take action to resolve the status if desired."
        Remediation      = 'To review and update policies: New-AzPolicyAssignment -Name "MCSB" -PolicyDefinitionId "/providers/Microsoft.Authorization/policySetDefinitions/securityCenterBuiltIn" -Scope "/subscriptions/{YourSubscriptionID}"'
        References       = @(
            @{ 'Name' = 'Security policies in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-policy-concept' },
            @{ 'Name' = 'Remediate recommendations'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/implement-security-recommendations' },
            @{ 'Name' = 'GS-7: Define and implement logging, threat detection, and incident response strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-7-define-and-implement-logging-threat-detection-and-incident-response-strategy' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz31011
{
	try
	{
		$Violation = @()
		# Actual Script
		$Recommendations = (Get-AzPolicySetDefinition | Where-Object {$_.DisplayName -eq "Microsoft cloud security benchmark"}).Parameter
		$HashTable = @{}
		$Recommendations.psobject.properties | ForEach {$HashTable[$_.Name] = $_.Value}

		foreach ($param in $HashTable.GetEnumerator()){
			if ($param.Value.DefaultValue -match 'Disabled|disabled'){
				$Violation += $param.Value.metadata.displayName
			}
		}
		
		# Validation
		if ($Violation.Count -igt 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISAz31011-DefaultDisabledMCSBenchmarkPolicies.txt"
			$endobject = Build-CISAz31011 -ReturnedValue ($Violation.Count) -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31011 -ReturnedValue "Microsoft Cloud Security Benchmark policies are not set to 'Enabled'" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31011 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31011