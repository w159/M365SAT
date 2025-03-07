# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz531
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz531"
        ID               = "5.3.1"
        Title            = "(L1) Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "SSL connectivity helps to provide a new layer of security by connecting the database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between the database server and client applications helps protect against 'man-in-the-middle' attacks by encrypting the data stream between the server and application."
        Impact           = "Failure to enforce secure transport may lead to interception of data in transit, exposing sensitive information to unauthorized access."
        Remediation      = "Use the following PowerShell script to remediate the issue: Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name require_secure_transport -Value on"
        References       = @(
            @{ 'Name' = 'TLS and SSL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking#tls-and-ssl' },
            @{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz531
{
    try
    {
        $Violation = @()
        $MySqlServers = Get-AzResource | Where-Object { $_.ResourceType -eq 'Microsoft.DBforMySQL/flexibleServers' }

        foreach ($MySqlServer in $MySqlServers) {
            $Setting = Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -ServerName $MySqlServer.Name -Name require_secure_transport
            if ($Setting.Value -ne 'on') {
                $Violation += $MySqlServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz531 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz531 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz531 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz531
