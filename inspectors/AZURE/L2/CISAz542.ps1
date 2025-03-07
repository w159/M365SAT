# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz542
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz542"
        ID               = "5.4.2"
        Title            = "(L2) Ensure That Private Endpoints Are Used Where Possible"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default Cosmos DB does not have private endpoints enabled and its traffic is public to the network."
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected."
        Impact           = "Only whitelisted services will have access to communicate with the Cosmos DB."
        Remediation      = 'Use the PowerShell script to remediate the issue: Update-AzMySqlServer -ResourceGroupName <server>.ResourceGroupName -Name <Server>.Name -ssl-enforcement Enabled'
        References       = @(
            @{ 'Name' = 'Configure Azure Private Link for an Azure Cosmos DB account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints?tabs=arm-bicep' },
            @{ 'Name' = 'Configure access to Azure Cosmos DB from virtual networks (VNet)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-vnet-service-endpoint' },
            @{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz542
{
    try
    {
        $Violation = @()
        $ResourceGroupNames = Get-AzResource | Select-Object ResourceGroupName -Unique
        foreach ($ResourceGroupName in $ResourceGroupNames) {
            $AzCosmosDBAccounts = Get-AzCosmosDBAccount -ResourceGroupName $ResourceGroupName.ResourceGroupName
            foreach ($AzCosmosDBAccount in $AzCosmosDBAccounts) {
                $Account = Get-AzCosmosDBAccount -ResourceGroupName $ResourceGroupName.ResourceGroupName -Name $AzCosmosDBAccount.Name
                if ($Account.PrivateEndpointConnections.PrivateLinkServiceConnectionState.Status -ne 'Approved') {
                    $Violation += $AzCosmosDBAccount.Name
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz542 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz542 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz542 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz542
