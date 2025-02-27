# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz516
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz516"
        ID               = "5.1.6"
        Title            = "(L1) Ensure that 'Auditing' Retention is 'greater than 90 days'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, SQL Server audit storage is disabled."
        ExpectedValue    = ">90 days"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access."
        Impact           = "Failure to maintain adequate auditing retention can result in insufficient data for investigation and increased risk of undetected security incidents."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzSqlServerAudit -ResourceGroupName "<resource group name>" -ServerName "<SQL Server name>" -BlobStorageTargetState/-EventHubTargetState/LogAnalyticsTargetState Enabled'
        References       = @(
            @{ 'Name' = 'Auditing for Azure SQL Database and Azure Synapse Analytics'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview?view=azuresql' },
            @{ 'Name' = 'LT-6: Configure log storage retention'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz516
{
    try
    {
        $Violation = @()
        $SQLServers = Get-AzSqlServer

        foreach ($SQLServer in $SQLServers) {
            $ServerAudits = Get-AzSqlServerAudit -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName

            ForEach ($ServerAudit in $ServerAudits) {
                if ($ServerAudit.LogAnalyticsTargetState -eq "Enabled")
                {
                    $InsightWorkSpace = Get-AzOperationalInsightsWorkspace | Where-Object {$_.ResourceId -eq $ServerAudit.WorkspaceResourceId}
                    if ($InsightWorkSpace.retentionInDays -lt 90){
                        $Violation += $SQLServer.ServerName
                    }
                }
                else
                {
                    if ($ServerAudit.RetentionInDays -lt 90){
                        $Violation += $SQLServer.ServerName
                    }
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz516 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz516 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz516 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz516
