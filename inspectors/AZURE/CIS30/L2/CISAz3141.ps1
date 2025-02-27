# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3141
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3141"
        ID               = "3.1.4.1"
        Title            = "(L2) nsure That Microsoft Defender for Containers Is Set To 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Containers provides security threat detection for containerized applications running in Azure Kubernetes Service (AKS), Azure Container Registry (ACR), and other supported environments. Enabling Defender for Containers helps to identify vulnerabilities, detect runtime threats, and provide behavioral analytics to improve overall security posture."
        Impact           = "Turning on Microsoft Defender for Containers incurs an additional cost per resource."
        Remediation      = 'To enable Microsoft Defender for Containers: Set-AzSecurityPricing -Name "Containers" -PricingTier "Standard"'
        References       = @(
            @{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
            @{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' },
            @{ 'Name' = 'Overview - Container protection in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction?tabs=defender-for-container-arch-aks' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3141
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "Containers" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$endobject = Build-CISAz3141 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3141 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3141 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3141