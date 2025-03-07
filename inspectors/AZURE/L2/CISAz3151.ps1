# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3151
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3151"
        ID               = "3.1.5.1"
        Title            = "(L1) Ensure That Microsoft Defender for Storage Is Set To 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling Microsoft Defender for Storage enhances security by providing integrated threat detection and protection for storage accounts. This feature helps to identify and respond to potential threats and vulnerabilities in the storage environment, ensuring comprehensive defense-in-depth."
        Impact           = "Turning on Microsoft Defender for Storage incurs an additional cost per resource."
        Remediation      = 'To enable Microsoft Defender for Storage: Set-AzSecurityPricing -Name "StorageAccounts" -PricingTier "Standard"'
        References       = @(
            @{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
            @{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3151
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "StorageAccounts" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$endobject = Build-CISAz3151 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3151 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3151 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3151