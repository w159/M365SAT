# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz612
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz612"
        ID               = "6.1.2"
        Title            = "(L1) Ensure Diagnostic Setting captures appropriate categories"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "No Diagnostic Setting is set"
        ExpectedValue    = "Administrative, Alert, Policy, Security"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting."
        Impact           = "Failure to capture diagnostic settings for appropriate categories may hinder security monitoring and incident response."
        Remediation      = "Use the following PowerShell script to remediate the issue: New-AzDiagnosticSetting"
        References       = @(
            @{ 'Name' = 'Diagnostic settings in Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings' },
            @{ 'Name' = 'Resource Manager template samples for diagnostic settings in Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-manager-diagnostic-settings?tabs=bicep' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz612
{
    try
    {
        $Violation = @()
        $SubscriptionId = Get-AzContext
        $Settings = ((Invoke-AzRestMethod -Uri "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview").Content | ConvertFrom-Json).value.properties.logs
        
        foreach ($Setting in $Settings) {
            if ($Setting.category -in @('Administrative', 'Alert', 'Policy', 'Security')) {
                if ($Setting.enabled -eq $false) {
                    $Violation += $Setting.category
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz612 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz612 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz612 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}

return Audit-CISAz612
