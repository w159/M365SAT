# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3135
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )


    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3135"
        ID               = "3.1.3.5"
        Title            = "(L2) Ensure File Integrity Monitoring (FIM) is Enabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "False"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "File Integrity Monitoring (FIM) is a critical security feature that detects unauthorized changes to files, helping identify potential malware activity or unauthorized modifications in the system. When FIM is enabled, critical system files are monitored for changes, providing an additional layer of protection against cyber threats."
        Impact           = "Endpoint protection requires additional licensing E.g. Defender for Servers plan 2."
        Remediation      = 'To enable File Integrity Monitoring (FIM): Set-AzSecurityPricing -Name "CloudPosture" -PricingTier "Standard" -Extension "[{"name":"FileIntegrityMonitoring","isEnabled":"True","additionalExtensionProperties":null}]"'
        References       = @(
            @{ 'Name' = 'File Integrity Monitoring in Microsoft Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview' },
            @{ 'Name' = 'File Integrity Monitoring using Microsoft Defender for Endpoint'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-enable-defender-endpoint' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3135
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		# Since this requires Defender for Servers Plan 2 I cannot audit this, but this is the URL you can check to determine. All you need to do is modify the eq statement to the corresponding value.
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq 'FileIntegrityMonitoring'}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$endobject = Build-CISAz3135 -ReturnedValue ($Settings.isEnabled) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3135 -ReturnedValue ($Settings.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3135 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3135