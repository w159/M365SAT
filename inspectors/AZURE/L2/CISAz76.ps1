# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz76
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz76"
        ID               = "7.6"
        Title            = "(L2) Ensure that Network Watcher is 'Enabled' for Azure Regions that are in use"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Network Watcher is automatically enabled. When you create or update a virtual network in your subscription."
        ExpectedValue    = "A NetworkWatcher"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure."
        Impact           = "There are additional costs per transaction to run and store network data. For high-volume networks these charges will add up quickly."
        Remediation      = 'Use the PowerShell script: New-AzNetworkWatcher'
        References       = @(
            @{ 'Name' = 'What is Azure Network Watcher?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview' },
            @{ 'Name' = 'Enable or disable Azure Network Watcher'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-create?tabs=portal' },
            @{ 'Name' = 'LT-4: Enable network logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-4-enable-network-logging-for-security-investigation' },
            @{ 'Name' = 'Network Watcher pricing'; 'URL' = 'https://azure.microsoft.com/en-ca/pricing/details/network-watcher/' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz76
{
    try
    {
        # Network Watcher Provisioning State Check
        $AffectedSettings = @()
        $AzNetworkWatchers = Get-AzNetworkWatcher -WarningAction SilentlyContinue

        foreach ($AzNetworkWatcher in $AzNetworkWatchers)
        {
            if ($AzNetworkWatcher.provisioningState -notmatch 'Succeeded')
            {
                $AffectedSettings += $AzNetworkWatcher.Name
            }
        }

        if ($AffectedSettings.Count -gt 0)
        {
            $FinalObject = Build-CISAz76 -ReturnedValue $AffectedSettings -Status "FAIL" -RiskScore "6" -RiskRating "Medium"
            return $FinalObject
        }
        else
        {
            $FinalObject = Build-CISAz76 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz76 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz76
