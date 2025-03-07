# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz616
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz616"
        ID               = "6.1.6"
        Title            = "(L1) Ensure that logging for Azure AppService 'HTTP logs' is enabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "KeySource: Microsoft.Storage"
        ExpectedValue    = "KeySource: Microsoft.Keyvault"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Capturing web requests can be important supporting information for security analysts performing monitoring and incident response activities. Once logging, these logs can be ingested into SIEM or other central aggregation point for the organization."
        Impact           = "Log consumption and processing will incur additional cost."
        Remediation      = "Use the following PowerShell script to remediate the issue: Set-AzStorageAccount"
        References       = @(
            @{ 'Name' = 'Enable diagnostics logging for apps in Azure App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz616
{
    try
    {
        # Web Apps-Based Checking
        $Violation = @()
        $WebApps = Get-AzWebApp -WarningAction SilentlyContinue -ProgressAction SilentlyContinue
        
        ForEach ($WebApp in $WebApps){
            if ($WebApp.Id.Contains('Microsoft.Web') -and $WebApp.Kind -ne 'functionapp'){
                $Settings = ((Invoke-AzRestMethod "https://management.azure.com/$($WebApp.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview").Content | ConvertFrom-Json).value.properties.logs
                if (-not [string]::IsNullOrEmpty($Settings)){
                    foreach ($Setting in $Settings){
                        if ($Setting.category -eq 'AppServiceHTTPLogs' -and $Setting.enabled -ne $true){
                            $Violation += $WebApp.Name
                        }
                    }
                }
                else{
                    $Violation += $WebApp.Name
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz616 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz616 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz616 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz616
