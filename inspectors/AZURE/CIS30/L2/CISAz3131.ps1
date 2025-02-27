# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3131
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3131"
        ID               = "3.1.3.1"
        Title            = "(L1) Ensure That Microsoft Defender for Servers Is Set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Servers provides enhanced security capabilities, including endpoint protection, vulnerability management, file integrity monitoring, and automated threat detection. It leverages Microsoft Security Response Center (MSRC) threat intelligence to detect suspicious activity, alert administrators, and enable proactive security measures. Enabling Defender for Servers ensures comprehensive protection for virtual machines running in Azure."
        Impact           = "Turning on Microsoft Defender for Servers in Microsoft Defender for Cloud incurs an additional cost per resource."
        Remediation      = 'To enable Microsoft Defender for Servers: Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"'
        References       = @(
            @{ 'Name' = 'Plan your Defender for Servers deployment'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-servers' },
            @{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3131
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name 'VirtualMachines' | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$endobject = Build-CISAz3131 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3131 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3131 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3131