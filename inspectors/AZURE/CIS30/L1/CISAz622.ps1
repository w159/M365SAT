# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz622
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz622"
        ID               = "6.2.2"
        Title            = "(L1) Ensure that Activity Log Alert exists for Delete Policy Assignment"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, no monitoring alerts are created."
        ExpectedValue    = "an Activity Log Alert Rule for Microsoft.Authorization/policyAssignments/delete"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Monitoring for delete policy assignment events gives insight into changes done in 'Azure policy - assignments' and can reduce the time it takes to detect unsolicited changes."
        Impact           = "Failure to create alerts for policy assignment deletions increases the risk of undetected changes."
        Remediation      = "Use the PowerShell script to create the necessary Activity Log Alert Rule: New-AzActivityLogAlert"
        References       = @(
            @{ 'Name' = 'Classic alerts in Azure Monitor to retire in June 2019'; 'URL' = 'https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement/' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
            @{ 'Name' = 'Azure Blueprints'; 'URL' = 'https://azure.microsoft.com/en-us/products/blueprints/' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz622
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $Subscriptions = Get-AzSubscription

        foreach ($Subscription in $Subscriptions){
            $LogAlert = Get-AzActivityLogAlert -SubscriptionId $Subscription.Id | Where-Object {$_.ConditionAllOf.Equal -match "Microsoft.Authorization/policyAssignments/delete"} | Select-Object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
            if ([string]::IsNullOrEmpty($LogAlert)){
                $Violation += $Subscription.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz622 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz622 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz622 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz622
