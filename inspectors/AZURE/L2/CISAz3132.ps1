# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz3132
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz3132"
        ID               = "3.1.3.2"
        Title            = "(L2) Ensure that 'Vulnerability assessment for machines' component status is set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Servers includes a built-in vulnerability assessment solution that helps detect unpatched software, insecure configurations, and OS vulnerabilities across Azure VMs. This feature requires **Defender for Servers Plan 2**. If you do not have this plan, consider using an alternative vulnerability assessment solution."
        Impact           = "Microsoft Defender for Servers plan 2 licensing is required, and configuration of Azure Arc introduces complexity beyond this recommendation."
        Remediation      = 'To enable Vulnerability Assessment for Machines. Follow the steps here: $Subscription = Get-AzSubscription; $body = @{ "kind" = "AzureServersSetting""properties" = @{ "selectedProvider" = "MdeTvm"}}; $url = "https://management.azure.com/subscriptions/$Subscription.Id/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/AzureServersSetting?api-version=2022-01-01-preview"; Invoke-RestMethod -Method Put -ContentType "application/json; charset=utf-8" -Authentication Bearer -Token (ConvertTo-SecureString -String (Get-AzAccessToken).token -AsPlainText) -Body (ConvertTo-Json $body -Depth 2) -Uri $url'        
        References       = @(
            @{ 'Name' = 'Plan your Defender for Servers deployment'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-servers' },
            @{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz3132
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		# Since this requires Defender for Servers Plan 2 I cannot audit this, but this is the URL you can check to determine. All you need to do is modify the eq statement to the corresponding value.
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq ''}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$endobject = Build-CISAz3132 -ReturnedValue ($Settings.isEnabled) -Status "FAIL" -RiskScore "2" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz3132 -ReturnedValue ($Settings.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz3132 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz3132