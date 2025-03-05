# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3143
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3143"
        ID               = "3.1.4.3"
        Title            = "(L2) Ensure that 'Agentless container vulnerability assessment' component status is 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Agentless container vulnerability scanning provides critical detection of vulnerable configurations within container images, whether they are running or stored. Enabling this feature ensures that security flaws in containers can be identified and remediated to prevent potential security risks."
        Impact           = "Endpoint protection requires additional licensing E.g. Defender for Servers plan CSPM or Defender for Containers plans."
        Remediation      = 'To enable Agentless Discovery for Kubernetes: Set-AzSecurityPricing -Name "CloudPosture" -PricingTier "Standard" -Extension "[{"name":"ContainerRegistriesVulnerabilityAssessments","isEnabled":"True","additionalExtensionProperties":null}]"'
        References       = @(
            @{ 'Name' = 'Overview - Container protection in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' },
            @{ 'Name' = 'How does Defender for Cloud collect data?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components?tabs=autoprovision-containers' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3143
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq 'ContainerRegistriesVulnerabilityAssessments'}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$endobject = Build-CISAz3143 -ReturnedValue ($Settings.isEnabled) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3143 -ReturnedValue ($Settings.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3143 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3143