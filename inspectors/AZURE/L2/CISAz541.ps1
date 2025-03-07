# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz541
{
    param (
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz541"
        ID               = "5.4.1"
        Title            = "(L2) Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Enabled"
        ExpectedValue    = "Enabled"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Selecting certain networks for your Cosmos DB to communicate restricts the number of networks including the internet that can interact with what is stored within the database and limiting your Cosmos DB to only communicate on whitelisted networks lowers its attack footprint."
        Impact           = "WARNING: Failure to whitelist the correct networks will result in a connection loss. \n WARNING: Changes to Cosmos DB firewalls may take up to 15 minutes to apply. Ensure that sufficient time is planned for remediation or changes to avoid disruption."
        Remediation      = 'Use the PowerShell Script to remediate the issue: Update-AzCosmosDBAccount -ResourceGroupName resourceGroupName -Name accountName -EnableVirtualNetwork 1'
        References       = @(
            @{ 'Name' = 'Configure Azure Private Link for an Azure Cosmos DB account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints?tabs=arm-bicep' },
            @{ 'Name' = 'Configure access to Azure Cosmos DB from virtual networks (VNet)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-vnet-service-endpoint' },
            @{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' }
        )
    }

    return $inspectorobject
}


function Audit-CISAz541
{
    try
    {
        $Violation = @()
        $ResourceGroupNames = Get-AzResource | Select-Object ResourceGroupName -Unique
        foreach ($ResourceGroupName in $ResourceGroupNames) {
            $AzCosmosDBAccounts = Get-AzCosmosDBAccount -ResourceGroupName $ResourceGroupName.ResourceGroupName
            foreach ($AzCosmosDBAccount in $AzCosmosDBAccounts) {
                $Account = Get-AzCosmosDBAccount -ResourceGroupName $ResourceGroupName.ResourceGroupName -Name $AzCosmosDBAccount.Name
                if ($Account.IsVirtualNetworkFilterEnabled -eq $false) {
                    $Violation += $AzCosmosDBAccount.Name
                }
            }
        }

        if ($Violation.Count -gt 0) {
            $FinalObject = Build-CISAz541 -ReturnedValue $Violation -Status "FAIL" -RiskScore "2" -RiskRating "Low"
            return $FinalObject
        }
        else {
            $FinalObject = Build-CISAz541 -ReturnedValue "No violations found" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $FinalObject
        }

        return $null
    }
    catch
    {
        $EndObject = Build-CISAz541 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occurred on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $EndObject
    }
}
return Audit-CISAz541
