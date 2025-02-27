# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz412
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz412"
        ID               = "4.12"
        Title            = "(L2) Ensure Storage Logging is Enabled for Queue Service for 'Read', 'Write', and 'Delete' requests"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "None"
        ExpectedValue    = "All"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Storage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis"
        Impact           = "Enabling this setting can have a high impact on the cost of the log analytics service and data storage used by logging more data per each request. Do not enable this without determining your need for this level of logging, and do not forget to check in on data usage and projected cost. Some users have seen their logging costs increase from 10 US Dollars per month to 10,000 US Dollars per month."
        Remediation      = "You can change the settings by executing the following PowerShell command: Set-AzStorageServiceLoggingProperty -ServiceType Queue -LoggingOperations read,write,delete -RetentionDays 90 -Context $MyContextObject"
        References       = @(
            @{ 'Name' = 'Azure Storage analytics logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging' },
            @{ 'Name' = 'LT-4: Enable network logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-4-enable-network-logging-for-security-investigation' },
            @{ 'Name' = 'Monitor Azure Queue Storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/queues/monitor-queue-storage?tabs=azure-portal' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz412
{
    try
    {
        $Violation = @()
        $Contexts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName, ResourceGroupName 

        foreach ($Context in $Contexts) {
            try {
                $StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $Context.ResourceGroupName -Name $Context.StorageAccountName -ErrorAction SilentlyContinue).Value[0]
                $Cont = New-AzStorageContext -StorageAccountName $Context.StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue
                $Logging = Get-AzStorageServiceLoggingProperty -ServiceType Queue -Context $Cont -ErrorAction SilentlyContinue

                if ($Logging.LoggingOperations -ne 'All') {
                    $Violation += $Context.StorageAccountName
                } 
            }
            catch {
                continue
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz412 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz412 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz412 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}

return Audit-CISAz412
