# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz525
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz525"
        ID               = "5.2.5"
        Title            = "(L1) Ensure 'Allow public access from any Azure service within Azure to this server' for PostgreSQL flexible server is disabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "The Azure Postgres firewall is set to block all access by default."
        ExpectedValue    = "Block all access by default."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks."
        Impact           = "Failure to restrict access to trusted Azure resources can increase the risk of unauthorized access to the server."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Remove-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name <ruleName>'
        References       = @(
            @{ 'Name' = 'Firewall rules in Azure Database for PostgreSQL - Flexible Server'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules' },
            @{ 'Name' = 'Create and manage Azure Database for PostgreSQL - Flexible Server firewall rules using the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-manage-firewall-cli' },
            @{ 'Name' = 'NS-1: Establish network segmentation boundaries'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries' },
            @{ 'Name' = 'NS-6: Deploy web application firewall'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-6-deploy-web-application-firewall' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz525
{
    try
    {
        $Violation = @()
        $PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/flexibleServers'}

        foreach ($PostGreServer in $PostGreServers){
            $Setting = Get-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name
            if (-not [string]::IsNullOrEmpty($Setting.StartIPAddress) -or -not [string]::IsNullOrEmpty($Setting.EndIPAddress)){
                $Violation += $PostGreServer.Name
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz525 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz525 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz525 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz525
