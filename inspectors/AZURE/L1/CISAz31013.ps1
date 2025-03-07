# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31013
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31013"
        ID               = "3.1.13"
        Title            = "(L1) Ensure 'Additional email addresses' is Configured with a Security Contact Email"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, there are no additional email addresses entered."
        ExpectedValue    = "At least 1 email address"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Microsoft Defender for Cloud emails the Subscription Owner about security alerts. Adding additional security contact email addresses ensures that key personnel in your organization's security team receive these alerts, reducing the risk of delayed response to potential threats."
        Impact           = "Without additional security contacts configured, security alerts may be missed if the Subscription Owner does not promptly review them, leading to slower incident response."
        Remediation      = 'To configure security contact email addresses: $securityContacts = @("security-team@example.com", "soc@example.com"); Set-AzSecurityContact -Email $securityContacts -NotifyAboutAlerts $true -NotifyAboutAlertsForAllResources $true'
        References       = @(
            @{ 'Name' = 'Configure email notifications for alerts and attack paths'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz31013
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties
		
		if ([string]::IsNullOrEmpty($Settings.emails))
		{
			$finalobject = Build-CISAz31013 -ReturnedValue ("No Emailaddresses specified") -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31013 -ReturnedValue $Settings.emails -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31013 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31013