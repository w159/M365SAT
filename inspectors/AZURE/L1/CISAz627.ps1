# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz627
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz627"
        ID               = "6.2.7"
        Title            = "(L1) Ensure that Activity Log Alert exists for Create or Update SQL Server Firewall Rule"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, no monitoring alerts are created."
        ExpectedValue    = "an Activity Log Alert Rule for Microsoft.Sql/servers/firewallRules/write"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Monitoring for Create or Update SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."
        Impact           = "There will be a substantial increase in log size if there are a large number of administrative actions on a server."
        Remediation      = "Use the following PowerShell script to remediate the issue: New-AzActivityLogAlert"
        References       = @(
            @{ 'Name' = 'Classic alerts in Azure Monitor to retire in June 2019'; 'URL' = 'https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement/' },
            @{ 'Name' = 'Create or edit an activity log, service health, or resource health alert rule'; 'URL' = 'https://learn.microsoft.com/en-in/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule?tabs=activity-log' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz627
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $Subscriptions = Get-AzSubscription

        foreach ($Subscription in $Subscriptions){
            $LogAlert = Get-AzActivityLogAlert -SubscriptionId $Subscription.Id | Where-Object {$_.ConditionAllOf.Equal -match "Microsoft.Sql/servers/firewallRules/write"} | Select-Object Location, Name, Enabled, ResourceGroupName, ConditionAllOf
            if ([string]::IsNullOrEmpty($LogAlert)){
                $Violation += $Subscription.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz627 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz627 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz627 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz627
