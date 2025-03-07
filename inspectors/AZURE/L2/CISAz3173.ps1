# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3173
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3173"
        ID               = "3.1.7.3"
        Title            = "(L2) Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling Microsoft Defender for Azure SQL Databases ensures that critical security functionality is in place to safeguard your databases from potential attacks. Defender helps discover and classify sensitive data, mitigate database vulnerabilities, and detect anomalies indicative of potential threats."
        Impact           = "Turning on Microsoft Defender for Azure SQL Databases incurs an additional cost per resource."
        Remediation      = 'To enable Microsoft Defender for Azure SQL Databases: Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"'       
        References       = @(
            @{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
            @{ 'Name' = 'Azure security baseline for Azure SQL Databases'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/sql-databases-security-baseline' },
            @{ 'Name' = 'Protect your databases with Defender for Databases'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-databases-plan' },
            @{ 'Name' = 'DP-2: Monitor anomalies and threats targeting sensitive data'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-2-monitor-anomalies-and-threats-targeting-sensitive-data' },
            @{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3173
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "SqlServers" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$endobject = Build-CISAz3173 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3173 -ReturnedValue ($AzSecuritySetting.PricingTier) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3173 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3173