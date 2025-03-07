# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz75
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz75"
        ID               = "7.5"
        Title            = "(L2) Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Disabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches."
        Impact           = "This will keep IP traffic logs for longer than 90 days. As a level 2, first determine your need to retain data, then apply your selection here. As this is data stored for longer, your monthly storage costs will increase depending on your data use."
        Remediation      = "No PowerShell Script Available"
        References       = @(
            @{ 'Name' = 'Flow logging for network security groups'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview' },
            @{ 'Name' = 'LT-6: Configure log storage retention'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz75
{
    try
    {
        # Network Watcher Flow Log Checking
        $Violation = @()
        $AzNetworkWatchers = Get-AzNetworkWatcher

        foreach ($AzNetworkWatcher in $AzNetworkWatchers)
        {
            $FlowLog = Get-AzNetworkWatcherFlowLog -NetworkWatcherName $AzNetworkWatcher.Name -ResourceGroupName $AzNetworkWatcher.ResourceGroupName
            if ([string]::IsNullOrEmpty($FlowLog))
            {
                $Violation += $AzNetworkWatcher.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz75 -ReturnedValue $Violation -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz75 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz75 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz75
