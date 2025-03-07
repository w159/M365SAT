# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz512
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz512"
        ID               = "5.1.2"
        Title            = "(L1) Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Allow access to Azure Services is set to NO"
        ExpectedValue    = "0"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Azure SQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters. By default, for a SQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services. Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet. In order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters."
        Impact           = "Disabling Allow Azure services and resources to access this server will break all connections to SQL server and Hosted Databases unless custom IP specific rules are added in Firewall Policy."
        Remediation      = 'You can change the settings in the URL written in PowerShellScript: Set-AzSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name> -FirewallRuleName <firewall rule name> -StartIpAddress <IP Address other than 0.0.0.0> -EndIpAddress <IP Address other than 0.0.0.0 or 255.255.255.255>'
        References       = @(
            @{ 'Name' = 'Configure a Windows Firewall for Database Engine Access'; 'URL' = 'https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-windows-firewall-for-database-engine-access?view=sql-server-2017' },
            @{ 'Name' = 'Azure SQL Database and Azure Synapse IP firewall rules'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure?view=azuresql' },
            @{ 'Name' = 'sp_set_database_firewall_rule (Azure SQL Database)'; 'URL' = 'https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-set-database-firewall-rule-azure-sql-database?view=azuresqldb-current' },
            @{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' },
            @{ 'Name' = 'Allow Azure services'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview?view=azuresql#allow-azure-services' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz512
{
    try
    {
        $Violation = @()
        $SQLServers = Get-AzSqlServer

        foreach ($SQLServer in $SQLServers) {
            $Server = Get-AzSqlServerFirewallRule -ResourceGroupName $SQLServer.ResourceGroupName -ServerName $SQLServer.ServerName
            if ($Server.StartIpAddress -eq "0.0.0.0" -or $Server.EndIpAddress -eq "0.0.0.0" -or $Server.FirewallRuleName -eq "firewallRules_AllowAllAzureIps") {
                $Violation += $SQLServer.ServerName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz512 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz512 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz512 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz512
