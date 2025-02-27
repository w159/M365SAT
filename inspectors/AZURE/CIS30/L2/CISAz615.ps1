# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz615
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz615"
        ID               = "6.1.5"
        Title            = "(L2) Ensure that Network Security Group Flow logs are captured and sent to Log Analytics"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Network Security Group logs are not sent to Log Analytics"
        ExpectedValue    = "NSG Flow logs are captured and sent to Log Analytics"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analyzing for lateral movement, etc."
        Impact           = "The impact of configuring NSG Flow logs is primarily one of cost and configuration. If deployed, it will create storage accounts that hold minimal amounts of data on a 5-day lifecycle before feeding to Log Analytics Workspace. This will increase the amount of data stored and used by Azure Monitor."
        Remediation      = "Use the PowerShell Script to remediate the issue."
        PowerShellScript = "No PowerShell Script Available"
        References       = @(
            @{ 'Name' = 'Tutorial: Log network traffic to and from a virtual machine using the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-tutorial' },
            @{ 'Name' = 'LT-4: Enable network logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-4-enable-network-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz615
{
    try
    {
        # Subscription-Based Checking
        $Violation = @()
        $NetworkWatchers = Get-AzNetworkWatcher

        foreach ($NetworkWatcher in $NetworkWatchers) {
            $nsgs = Get-AzNetworkSecurityGroup
            foreach ($nsg in $nsgs) {
                $Setting = Get-AzNetworkWatcherFlowLogStatus -NetworkWatcher $NetworkWatcher -TargetResourceId $nsg.Id
                if ($Setting.Enabled -eq $False) {
                    $Violation += "$($NetworkWatcher.Name): $($nsg.Name)"
                }
            }    
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz615 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz615 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }
    }
    catch
    {
        $EndObject = Build-CISAz615 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz615
