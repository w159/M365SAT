# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz517
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz517"
        ID               = "5.1.7"
        Title            = "(L1) Ensure Public Network Access is Disabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, SQL Server audit storage is disabled."
        ExpectedValue    = ">90 days"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A secure network architecture requires carefully constructed network segmentation. Public Network Access tends to be overly permissive and introduces unintended vectors for threat activity."
        Impact           = "Some architectural consideration may be necessary to ensure that required network connectivity is still made available. No additional cost or performance impact is required to deploy this recommendation."
        Remediation      = 'You can change the settings by executing the following PowerShell command: Set-AzSqlServer -ServerName <SQLServerName> -ResourceGroupName <ResourceGroupName> -SqlAdministratorPassword $SecureString -PublicNetworkAccess "Enabled"'
        References       = @(
            @{ 'Name' = 'NS-2: Secure cloud services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls' },
            @{ 'Name' = 'Deny public network access'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal#deny-public-network-access' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz517
{
    try
    {
        $Violation = @()
        $SQLServers = Get-AzSqlServer

        foreach ($SQLServer in $SQLServers) {
            if ($SQLServer.PublicNetworkAccess -eq 'Enabled') {
                $Violation += $SQLServer.ServerName
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz517 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz517 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz517 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz517
