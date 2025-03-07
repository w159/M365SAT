# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31014
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31014"
        ID               = "3.1.14"
        Title            = "(L1) Ensure That 'Notify about alerts with the following severity' is Set to 'High'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "High"
        ExpectedValue    = "High"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling security alert emails ensures that security alerts classified as 'High' severity are sent to the appropriate recipients. This helps ensure that critical security issues are promptly addressed and mitigated."
        Impact           = "If high-severity security alerts are not configured to notify the appropriate personnel, critical security incidents may go unnoticed, leading to increased risk exposure."
        Remediation      = 'To configure security alerts: Set-AzSecurityContact -NotifyAboutAlerts $true -AlertNotifications "High"'
        References       = @(
            @{ 'Name' = 'Configure email notifications for alerts and attack paths'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz31014
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties | select-object alertNotifications -ExpandProperty alertNotifications -ErrorAction SilentlyContinue
		
		if ($Settings.minimalSeverity -notmatch "High")
		{
			$endobject = Build-CISAz31014 -ReturnedValue ($Settings.minimalSeverity) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31014 -ReturnedValue ($Settings.minimalSeverity) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31014 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31014