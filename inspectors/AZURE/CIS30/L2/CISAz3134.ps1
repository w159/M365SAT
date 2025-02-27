# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3134
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3134"
        ID               = "3.1.3.4"
        Title            = "(L2) Ensure that 'Agentless scanning for machines' component status is set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Cloud provides agentless vulnerability scanning for machines, helping identify security misconfigurations, outdated software, and threats to workloads in your environment. Enabling this feature improves security visibility and risk assessment without requiring additional software agents."
        Impact           = "Endpoint protection requires additional licensing E.g. Defender for Servers plan 2 or Defender CSPM."
        Remediation      = 'To enable Agentless scanning for machines: Set-AzSecurityPricing -Name "CloudPosture" -PricingTier "Standard" -Extension "[{"name":"AgentlessVmScanning","isEnabled":"True","additionalExtensionProperties":{"ExclusionTags":"[{\"key\":\"Microsoft\",\"value\":\"Defender\"},{\"key\":\"For\",\"value\":\"Cloud\"}]"}}]"'
        References       = @(
            @{ 'Name' = 'Agentless machine scanning'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection' },
            @{ 'Name' = 'Enable agentless scanning for VMs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-agentless-scanning-vms' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3134
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		# Actual Script
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq 'AgentlessVmScanning'}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$endobject = Build-CISAz3134 -ReturnedValue ($Settings.isEnabled) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3134 -ReturnedValue ($Settings.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3134 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3134