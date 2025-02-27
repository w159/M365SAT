# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3133
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3133"
        ID               = "3.1.3.3"
        Title            = "(L2) Ensure that 'Endpoint protection' component status is set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Endpoint provides advanced Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. Enabling this integration helps detect and respond to sophisticated threats targeting endpoints in the environment."
        Impact           = "Endpoint protection requires additional licensing E.g. Defender for Servers plan 1 or 2."
        Remediation      = 'To enable Microsoft Defender for Endpoint: Set-AzSecuritySetting -SettingName "WDATP" -SettingKind "DataExportSettings" -Enabled $true; Set-AzSecuritySetting -SettingName "WDATP" -SettingKind "AlertSyncSettings" -Enabled $true;'
        References       = @(
            @{ 'Name' = 'Understand endpoint detection and response'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows' },
            @{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr' },
            @{ 'Name' = 'ES-2: Use modern anti-malware software'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-2-use-modern-anti-malware-software' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3133
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq "WDATP"}
		
		# Validation
		if ($AzSecuritySetting.Enabled -eq $False)
		{
			$endobject = Build-CISAz3133 -ReturnedValue ($AzSecuritySetting.Enabled) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3133 -ReturnedValue ($AzSecuritySetting.Enabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3133 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3133