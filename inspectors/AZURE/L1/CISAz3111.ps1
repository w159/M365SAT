# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3111
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3111"
        ID               = "3.1.1.1"
        Title            = "(L1) Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "On"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Cloud can automatically provision the Microsoft Monitoring Agent (MMA) on Azure VMs to collect security-related data. The agent enables security monitoring for system updates, OS vulnerabilities, endpoint protection, and provides security alerts. If auto-provisioning is turned off, security monitoring may be incomplete, leading to gaps in security visibility."
        Impact           = "Disabling auto-provisioning prevents the collection of critical security logs and configuration data from Azure VMs, reducing visibility into potential threats and vulnerabilities."
        Remediation      = 'To enable auto-provisioning of the Log Analytics Agent: Set-AzSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision'
        References       = @(
            @{ 'Name' = 'Microsoft Defender for Cloud data security'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-security' },
            @{ 'Name' = 'How does Defender for Cloud collect data?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components' },
            @{ 'Name' = 'LT-5: Centralize security log management and analysis'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3111
{
	try
	{
		# Actual Script
		$AutoProvisioningSetting = Get-AzSecurityAutoProvisioningSetting | Select-Object Name, AutoProvision
		
		# Validation
		if ($AutoProvisioningSetting.AutoProvision -eq 'Off')
		{
			$endobject = Build-CISAz3111 -ReturnedValue ($AutoProvisioningSetting.AutoProvision) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3111 -ReturnedValue ($AutoProvisioningSetting.AutoProvision) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3111 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3111