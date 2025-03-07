# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz515
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz515"
        ID               = "5.1.5"
        Title            = "(L1) Ensure that 'Data encryption' is set to 'On' on a SQL Database"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Azure SQL Database transparent data encryption helps protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application."
        Impact           = "Failure to enable encryption on SQL Databases exposes data to the risk of unauthorized access and breach."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName <ResourceGroupName> -ServerName <SQLServerName> -DatabaseName <DatabaseName> -State "Enabled"'
        References       = @(
            @{ 'Name' = 'Transparent data encryption for SQL Database, SQL Managed Instance, and Azure Synapse Analytics'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview?view=azuresql&tabs=azure-portal' },
            @{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz515
{
    try
    {
        $Violation = @()
        $SQLServers = Get-AzSqlServer

        foreach ($SQLServer in $SQLServers) {
            $Databases = Get-AzSqlDatabase -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
            ForEach ($Database in $Databases) {
                $Encryption = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName -DatabaseName $Database.DatabaseName
                if ($Encryption.State -eq "Disabled" -and $Encryption.DatabaseName -ne "master") {
                    $Violation += $SQLServer.ServerName
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz515 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz515 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz515 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz515
