# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz527
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz527"
        ID               = "5.2.7"
        Title            = "(L1) Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL single server"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Off"
        ExpectedValue    = "On"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling log_disconnections helps PostgreSQL Database to log the end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
        Impact           = "Enabling this setting will enable a log of all disconnections. If this is enabled for a high traffic server, the log may grow exponentially."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_disconnections -Value on'
        References       = @(
            @{ 'Name' = 'What happens to Azure Database for PostgreSQL - Single Server after the retirement announcement?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/whats-happening-to-postgresql-single-server' },
            @{ 'Name' = 'What is the migration service in Azure Database for PostgreSQL?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/migrate/migration-service/overview-migration-service-postgresql' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz527
{
    try
    {
        $Violation = @()
        $PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/servers'}

        foreach ($PostGreServer in $PostGreServers) {
            $Setting = Get-AzPostgreSqlConfiguration -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name -Name log_disconnections
            if ($Setting.Value -ne 'on') {
                $Violation += $PostGreServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz527 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz527 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz527 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz527
