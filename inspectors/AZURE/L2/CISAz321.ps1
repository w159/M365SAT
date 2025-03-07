# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz321
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz321"
        ID               = "3.2.1"
        Title            = "(L1) Ensure that Microsoft Defender for IoT Hub is set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "IoT devices are typically not patched and are potential attack vectors. Using Microsoft Defender for IoT allows detection and mitigation of IoT-related security threats by centrally managing and monitoring these devices."
        Impact           = "Enabling Microsoft Defender for IoT will incur additional charges dependent on the level of usage."
        Remediation      = 'You can change the settings in the URL written: https://portal.azure.com/#browse/Microsoft.Devices%2FIotHubs'
        References       = @(
            @{ 'Name' = 'Microsoft Defender for IoT'; 'URL' = 'https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-iot#overview' },
            @{ 'Name' = 'Microsoft Defender for IoT KB'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-iot/' },
            @{ 'Name' = 'Microsoft Defender for IoT Pricing'; 'URL' = 'https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-iot-pricing' },
            @{ 'Name' = 'Azure security baseline for Microsoft Defender for IoT'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/microsoft-defender-for-iot-security-baseline' },
            @{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' },
            @{ 'Name' = 'Quickstart: Enable Microsoft Defender for IoT on your Azure IoT Hub'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-iot/device-builders/quickstart-onboard-iot-hub' }
        )
    }
    return $inspectorobject
}

#AuditScript
function Audit-CISAz321
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/iotSecuritySolutions?api-version=2019-08-01").content | ConvertFrom-Json)
		
		#validation
		if ([string]::IsNullOrEmpty($Settings.value))
		{
			$endobject = Build-CISAz321 -ReturnedValue ("No Microsoft Defender for IoT Hub available!") -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz321 -ReturnedValue ($Settings.value) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz321 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz321