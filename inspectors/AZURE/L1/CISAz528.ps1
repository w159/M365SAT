# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz528
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $InspectorObject = New-Object PSObject -Property @{
        UUID             = "CISAz528"
        ID               = "5.2.8"
        Title            = "(L1) Ensure 'Infrastructure double encryption' for PostgreSQL single server is 'Enabled'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, double encryption is disabled."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "If Double Encryption is enabled, another layer of encryption is implemented at the hardware level before the storage or network level. Information will be encrypted before it is even accessed, preventing both interception of data in motion if the network layer encryption is broken and data at rest in system resources such as memory or processor cache. Encryption will also be in place for any backups taken of the database, so the key will secure access the data in all forms. For the most secure implementation of key-based encryption, it is recommended to use a Customer Managed asymmetric RSA2048 Key in Azure Key Vault."
        Impact           = "The read and write speeds to the database will be impacted if both default encryption and Infrastructure Encryption are checked, as a secondary form of encryption requires more resource overhead for the cryptography of information. This cost is justified for information security. Customer managed keys are recommended for the most secure implementation, leading to overhead of key management. The key will also need to be backed up in a secure location, as loss of the key will mean loss of the information in the database."
        Remediation      = 'Use the following PowerShell script to remediate the issue: Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name infrastructureEncryption -Value enabled'
        References       = @(
            @{ 'Name' = 'What happens to Azure Database for PostgreSQL - Single Server after the retirement announcement?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/whats-happening-to-postgresql-single-server' },
            @{ 'Name' = 'What is the migration service in Azure Database for PostgreSQL?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/migrate/migration-service/overview-migration-service-postgresql' }
        )
    }

    return $InspectorObject
}


function Audit-CISAz528
{
    try
    {
        $Violation = @()
        $PostGreServers = Get-AzResource | Where-Object { $_.ResourceType -eq 'Microsoft.DBforPostgreSQL/servers' }

        foreach ($PostGreServer in $PostGreServers) {
            $Configuration = Get-AzPostgreSqlServer -ResourceGroupName $PostGreServer.ResourceGroupName -Name $PostGreServer.Name
            if ($Configuration.InfrastructureEncryption -eq $false) {
                $Violation += $PostGreServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz528 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz528 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz528 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz528
