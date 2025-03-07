# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz611
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz611"
        ID               = "6.1.1"
        Title            = "(L1) Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "All False"
        ExpectedValue    = "All True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription."
        Impact           = "Failure to define diagnostic settings may result in a lack of security activity visibility within an Azure subscription."
        Remediation      = "Use the following PowerShell script to remediate the issue: New-AzDiagnosticSetting"
        References       = @(
            @{ 'Name' = 'Azure Monitor data sources and data collection methods'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/data-sources#export-the-activity-log-with-a-log-profile' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz611
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $SubscriptionId = Get-AzContext
        $Settings = ((Invoke-AzRestMethod -Uri "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview").Content | ConvertFrom-Json).value.properties.logs
        
        foreach ($Setting in $Settings) {
            if ($Setting.enabled -eq $false) {
                $Violation += $Setting.category
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz611 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz611 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz611 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz611
