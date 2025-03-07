# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz511
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz511"
        ID               = "5.1.1"
        Title            = "(L1) Ensure that 'Auditing' is set to 'On'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Disabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted."
        Impact           = "Failure to enable auditing on SQL servers increases the risk of undetected unauthorized activity, making forensic investigation and compliance adherence more difficult."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzSqlServerAudit -ResourceGroupName <RGNAME> -ServerName <SQLServername> -RetentionInDays 90 -LogAnalyticsTargetState Enabled -EventHubTargetState Enabled -BlobStorageTargetState Enabled'
        References       = @(
            @{ 'Name' = 'Remediate recommendations'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/implement-security-recommendations' },
            @{ 'Name' = 'Auditing for Azure SQL Database and Azure Synapse Analytics'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview?view=azuresql' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz511
{
    try
    {
        $Violation = @()
        $SQLServers = Get-AzSqlServer

        foreach ($SQLServer in $SQLServers) {
            $Server = Get-AzSqlServerAudit -ResourceGroupName $SQLServer.ResourceGroupName -ServerName $SQLServer.ServerName
            if ($Server.BlobStorageTargetState -eq "Disabled" -or $Server.EventHubTargetState -eq "Disabled" -or $Server.LogAnalyticsTargetState -eq "Disabled") {
                $Violation += $SQLServer.ServerName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz511 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz511 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz511 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz511