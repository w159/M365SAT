# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz640
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz640"
        ID               = "6.4"
        Title            = "(L1) Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Application Insights are not enabled by default."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A lack of monitoring reduces the visibility into the data plane, and therefore an organization's ability to detect reconnaissance, authorization attempts or other malicious activity. Unlike Activity Logs, Resource Logs are not enabled by default. Specifically, without monitoring it would be impossible to tell which entities had accessed a data store that was breached. In addition, alerts for failed attempts to access APIs for Web Services or Databases are only possible when logging is enabled."
        Impact           = "Costs for monitoring varies with Log Volume. Not every resource needs to have logging enabled. It is important to determine the security classification of the data being processed by the given resource and adjust the logging based on which events need to be tracked. This is typically determined by governance and compliance requirements."
        Remediation      = 'Use the PowerShell script to enable diagnostic settings for resources: New-AzDiagnosticSetting'
        References       = @(
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
            @{ 'Name' = 'LT-5: Centralize security log management and analysis'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis' },
            @{ 'Name' = 'Monitor Azure resources with Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/monitor-azure-resource' },
            @{ 'Name' = 'Supported Resource log categories for Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/logs-index' },
            @{ 'Name' = 'Azure security logging and auditing'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/log-audit' },
            @{ 'Name' = 'Send Azure Monitor Activity log data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=powershell' },
            @{ 'Name' = 'Azure Key Vault logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/logging?tabs=Vault' },
            @{ 'Name' = 'Azure Monitor data sources and data collection methods'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/data-sources' },
            @{ 'Name' = 'Common and service-specific schemas for Azure resource logs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-logs-schema' },
            @{ 'Name' = 'Diagnostic logs - Azure Content Delivery Network'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz640
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $AzResources = Get-AzResource

        foreach ($AzResource in $AzResources){
            $DiagnosticSetting = Get-AzDiagnosticSetting -ResourceId $AzResource.Id -ErrorAction SilentlyContinue
            if ([string]::IsNullOrEmpty($DiagnosticSetting)){
                $Violation += $AzResource.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz640 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz640 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz640 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz640
