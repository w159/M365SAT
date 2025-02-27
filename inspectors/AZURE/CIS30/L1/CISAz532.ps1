# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz532
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $InspectorObject = New-Object PSObject -Property @{
        UUID             = "CISAz532"
        ID               = "5.3.2"
        Title            = "(L1) Ensure server parameter 'tls_version' is set to 'TLSv1.2' (or higher) for MySQL flexible server"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "TLSv1.2"
        ExpectedValue    = "TLSv1.2"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "TLS connectivity helps to provide a new layer of security by connecting the database server to client applications using Transport Layer Security (TLS). Enforcing TLS connections between the database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application."
        Impact           = "Failure to enforce TLS connections increases the risk of sensitive data being intercepted by malicious actors."
        Remediation      = "Use the following PowerShell script to remediate the issue: Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name tls_version -Value TLSv1.2"
        References       = @(
            @{ 'Name' = 'TLS and SSL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking#tls-and-ssl' },
            @{ 'Name' = 'Connect to Azure Database for MySQL - Flexible Server with encrypted connections'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit' }
        )
    }

    return $InspectorObject
}


function Audit-CISAz532
{
    try
    {
        $Violation = @()
        $MySqlServers = Get-AzResource | Where-Object { $_.ResourceType -eq 'Microsoft.DBforMySQL/flexibleServers' }

        foreach ($MySqlServer in $MySqlServers) {
            $Setting = Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -ServerName $MySqlServer.Name -Name tls_version
            if ($Setting.Value -ne 'TLSv1.2') {
                $Violation += $MySqlServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz532 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz532 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz532 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz532
