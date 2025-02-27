# Benchmark: CIS Microsoft Azure v3.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz337
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )

    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz337"
        ID               = "3.3.7"
        Title            = "(L2) Ensure that Private Endpoints are Used for Azure Key Vault"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default, Private Endpoints are not enabled for any services within Azure."
        ExpectedValue    = "Private Endpoints are enabled for any services within Azure."
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Private endpoints will keep network requests to Azure Key Vault limited to the endpoints attached to the resources that are whitelisted to communicate with each other. Assigning the Key Vault to a network without an endpoint will allow other resources on that network to view all traffic from the Key Vault to its destination. In spite of the complexity in configuration, this is recommended for high security secrets."
        Impact           = "Incorrect or poorly-timed changing of network configuration could result in service interruption. There are also additional costs tiers for running a private endpoint per petabyte or more of networking traffic."
        Remediation      = 'Use the PowerShell Script to remediate the issue: Update-AzKeyVault -ResourceGroupName <RESOURCE GROUP NAME> -VaultName <KEY VAULT NAME> -EnableRbacAuthorization $True'
        References       = @(
            @{ 'Name' = 'What is a private endpoint?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview' },
            @{ 'Name' = 'Use private endpoints for Azure Storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints' },
            @{ 'Name' = 'Azure Private Link pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/private-link/' },
            @{ 'Name' = 'Integrate Key Vault with Azure Private Link'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service?tabs=portal' },
            @{ 'Name' = 'Quickstart: Use the Azure portal to create a virtual network'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-network/quick-create-portal' },
            @{ 'Name' = 'Tutorial: Connect to a storage account using an Azure Private Endpoint'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-storage-portal?tabs=dynamic-ip' },
            @{ 'Name' = 'What is Azure Bastion?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/bastion/bastion-overview' },
            @{ 'Name' = 'Create an additional DNS record'; 'URL' = 'https://learn.microsoft.com/en-us/azure/dns/private-dns-getstarted-cli#create-an-additional-dns-record' },
            @{ 'Name' = 'DP-8: Ensure security of key and certificate repository'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz337
{
    try
    {
        $Violation = @()
        $AzKeyVaults = Get-AzKeyVault
        foreach ($AzKeyVault in $AzKeyVaults){
            $PrivateEndpointConnection = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzKeyVault.ResourceId
            if ([string]::IsNullOrEmpty($PrivateEndpointConnection)){
                $Violation += $AzKeyVault.VaultName
            }
        }

        #validation
        if ($Violation.count -gt 0)
        {
            $finalobject = Build-CISAz337 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
            return $finalobject
        }
        else
        {
            $finalobject = Build-CISAz337 -ReturnedValue "All Key Vaults have Private Endpoints enabled" -Status "PASS" -RiskScore "0" -RiskRating "None"
            return $finalobject
        }
        return $null
    }
    catch
    {
        $endobject = Build-CISAz337 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
        Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
        Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
        return $endobject
    }
}

return Audit-CISAz337
