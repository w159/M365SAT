# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz31012
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz31012"
        ID               = "3.1.12"
        Title            = "(L1) Ensure That 'All users with the following roles' is set to 'Owner'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Owner"
        ExpectedValue    = "Owner"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling security alert emails for subscription Owners ensures that critical security alerts are received directly by individuals with administrative privileges. This helps ensure prompt awareness and mitigation of potential security issues."
        Impact           = "Without security alerts enabled for Owners, crucial notifications about security risks may go unnoticed, increasing response times and exposure to threats."
        Remediation      = 'To configure security alert emails: https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
        References       = @(
            @{ 'Name' = 'Configure email notifications for alerts and attack paths'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' },
            @{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz31012
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties | select-object notificationsByRole -ExpandProperty notificationsByRole -ErrorAction SilentlyContinue | select-object roles -ExpandProperty roles -ErrorAction SilentlyContinue
		
		if ($Settings -notmatch 'Owner')
		{
			$endobject = Build-CISAz31012 -ReturnedValue ($Settings) -Status "FAIL" -RiskScore "1" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz31012 -ReturnedValue "'All users with the following roles' is set to 'Owner'" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz31012 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz31012