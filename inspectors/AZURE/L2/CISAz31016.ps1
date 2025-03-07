# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31016
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31016"
        ID               = "3.1.16"
        Title            = "(L2) Ensure That Microsoft Defender for DNS Is Set To 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for DNS scans DNS lookups within your Azure subscription and compares them to a dynamic list of potential security threats. Enabling Defender for DNS ensures that your subscription is protected from security threats that may appear due to a breach."
        Impact           = "Enabling Microsoft Defender for DNS requires enabling Microsoft Defender for your subscription. Both will incur additional charges, with Defender for DNS being a small amount per million queries."
        Remediation      = 'Use the PowerShell script to remediate the issue: Set-AzSecurityPricing -Name "DNS" -PricingTier "Standard"'
        References       = @(
            @{ 'Name' = 'Connect your Azure subscriptions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription' },
            @{ 'Name' = 'Azure security baseline for Azure DNS'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-dns-security-baseline' },
            @{ 'Name' = 'Microsoft Defender for Cloud pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/' },
            @{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
            @{ 'Name' = 'Respond to Microsoft Defender for DNS alerts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-alerts' },
            @{ 'Name' = 'NS-10: Ensure Domain Name System (DNS) security'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-10-ensure-domain-name-system-dns-security' },
            @{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz31016
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "DNS" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$endobject = Build-CISAz31016 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31016 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31016 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31016