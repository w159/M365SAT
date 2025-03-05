# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz523
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz523"
        ID               = "5.2.3"
        Title            = "(L1) Ensure server parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL flexible server"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling connection throttling helps the PostgreSQL Database to set the verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
        Impact           = "Failure to enable connection throttling could allow an overload of requests, leading to degraded system performance or even denial of service."
        Remediation      = 'Use the PowerShell script to remediate the issue: Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name connection_throttle.enable -Value on'
        References       = @(
            @{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Flexible Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal' },
            @{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
            @{ 'Name' = 'Configure logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-logging#configure-logging' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz523
{
    try
    {
        $Violation = @()
        $PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/flexibleServers'}

        foreach ($PostGreServer in $PostGreServers) {
            $Setting = Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name -Name connection_throttle.enable
            if ($Setting.Value -ne 'on') {
                $Violation += $PostGreServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz523 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz523 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz523 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz523
