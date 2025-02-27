# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz650
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz650"
        ID               = "6.5"
        Title            = "(L2) Ensure that SKU Basic/Consumption is not used on artifacts that need to be monitored (Particularly for Production Workloads)"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Application Insights are not enabled by default."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Typically, production workloads need to be monitored and should have an SLA with Microsoft, using Basic SKUs for any deployed product will mean that those capabilities do not exist."
        Impact           = "All resources should be either tagged or in separate Management Groups/Subscriptions. There might be cost increases."
        Remediation      = "Use the PowerShell Script to remediate the issue."
        References       = @(
            @{ 'Name' = 'Compare support plans'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview' },
            @{ 'Name' = 'Support scope and responsiveness'; 'URL' = 'https://azure.microsoft.com/en-us/support/plans/response/' }
        )
    }

    return $inspectorobject
}

function Audit-CISAz650
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $AzResources = Get-AzResource | Where-Object { $_.Sku -EQ "Basic" }

        foreach ($AzResource in $AzResources){
            $Violation += $AzResource.Name
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz650 -ReturnedValue $Violation -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz650 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "Informational"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz650 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz650
