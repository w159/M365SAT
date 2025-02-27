# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz534
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz534"
        ID               = "5.3.4"
        Title            = "(L1) Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "CONNECTION"
        ExpectedValue    = "CONNECTION"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling CONNECTION helps MySQL Database to log items such as successful and failed connection attempts to the server. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."
        Impact           = "There are further costs incurred for storage of logs. For high traffic databases these logs will be significant. Determine your organization's needs before enabling."
        Remediation      = 'Use the PowerShell script to remediate the issue: Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name audit_log_events -Value CONNECTION'
        References       = @(
            @{ 'Name' = 'Track database activity with Audit Logs in Azure Database for MySQL - Flexible Server'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-audit-logs' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
            @{ 'Name' = 'Tutorial: Configure audit logs by using Azure Database for MySQL - Flexible Server'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit' },
            @{ 'Name' = 'Configure auditing by using the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit#configure-auditing-by-using-the-azure-cli' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz534
{
    try
    {
        $Violation = @()
        $MySqlServers = Get-AzResource | Where-Object { $_.ResourceType -eq 'Microsoft.DBforMySQL/flexibleServers' }

        foreach ($MySqlServer in $MySqlServers) {
            $Configuration = Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -ServerName $MySqlServer.Name -Name audit_log_events
            if ($Configuration.Value -ne 'CONNECTION') {
                $Violation += $MySqlServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz534 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz534 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz534 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz534
