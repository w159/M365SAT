# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz413
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz413"
        ID               = "3.13"
        Title            = "(L2) Ensure Storage logging is Enabled for Blob Service for 'Read', 'Write', and 'Delete' requests"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "None"
        ExpectedValue    = "All"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Storage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor each individual request to a storage service for increased security or diagnostics. Requests are logged on a best-effort basis."
        Impact           = "Being a level 2, enabling this setting can have a high impact on the cost of data storage used for logging more data per each request. Do not enable this without determining your need for this level of logging or forget to check in on data usage and projected cost."
        Remediation      = "You can change the settings by executing the following PowerShell command: Set-AzStorageServiceLoggingProperty -ServiceType Blob -LoggingOperations read,write,delete -RetentionDays 90 -Context $MyContextObject"
        References       = @(
            @{ 'Name' = 'Azure Storage analytics logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz413
{
    try
    {
        $Violation = @()
        $Contexts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName, ResourceGroupName 

        foreach ($Context in $Contexts) {
            try {
                $StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $Context.ResourceGroupName -Name $Context.StorageAccountName -ErrorAction SilentlyContinue).Value[0]
                $Cont = New-AzStorageContext -StorageAccountName $Context.StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue
                $Logging = Get-AzStorageServiceLoggingProperty -ServiceType Blob -Context $Cont -ErrorAction SilentlyContinue

                if ($Logging.LoggingOperations -ne 'All') {
                    $Violation += $Context.StorageAccountName
                } 
            }
            catch {
                continue
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz413 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz413 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz413 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}

return Audit-CISAz413
