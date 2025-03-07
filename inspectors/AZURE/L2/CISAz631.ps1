# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz631
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz631"
        ID               = "6.3.1"
        Title            = "(L2) Ensure Application Insights are Configured"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Application Insights are not enabled by default."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Configuring Application Insights provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost-saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Metrics and Telemetry data provide organizations with a proactive approach to cost savings by monitoring an application's performance, while the trace logging data provides necessary details in a reactive incident response scenario by helping organizations identify the potential source of an incident within their application."
        Impact           = "Because Application Insights relies on a Log Analytics Workspace, an organization will incur additional expenses when using this service."
        Remediation      = 'Use the following PowerShell script to enable Application Insights: New-AzApplicationInsights'
        References       = @(
            @{ 'Name' = 'Application Insights overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz631
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $ApplicationInsights = Get-AzApplicationInsights

        foreach ($ApplicationInsight in $ApplicationInsights){
            if ([string]::IsNullOrEmpty($ApplicationInsight)){
                $Violation += "No ApplicationInsights Configured"
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz631 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz631 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz631 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz631
